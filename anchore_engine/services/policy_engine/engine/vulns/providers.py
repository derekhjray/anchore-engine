import datetime
import hashlib
import json
import time

from sqlalchemy import asc, func, orm

from anchore_engine import version
from anchore_engine.clients.services.common import get_service_endpoint
from anchore_engine.common.helpers import make_response_error
from anchore_engine.db import DistroNamespace
from anchore_engine.db import (
    Image,
    ImageCpe,
    VulnDBMetadata,
    VulnDBCpe,
    get_thread_scoped_session as get_session,
    select_nvd_classes,
)
from anchore_engine.db import Vulnerability, ImagePackageVulnerability
from anchore_engine.services.policy_engine.api.models import (
    Vulnerability as VulnerabilityModel,
    VulnerabilityMatch,
    Artifact,
    ImageVulnerabilitiesReport,
    VulnerabilitiesReportMetadata,
    CvssCombined,
    FixedArtifact,
    CvssScore,
    Match,
)
from anchore_engine.services.policy_engine.engine.feeds.feeds import (
    have_vulnerabilities_for,
)
from anchore_engine.services.policy_engine.engine.vulnerabilities import (
    merge_nvd_metadata_image_packages,
    merge_nvd_metadata,
    get_imageId_to_record,
)
from anchore_engine.services.policy_engine.engine.vulns.scanners import (
    LegacyScanner,
)
from anchore_engine.subsys import logger as log
from anchore_engine.utils import timer

# Disabled by default, can be set in config file. Seconds for connection to cache for policy evals
DEFAULT_CACHE_CONN_TIMEOUT = -1
# Disabled by default, can be set in config file. Seconds for first byte timeout for policy eval cache
DEFAULT_CACHE_READ_TIMEOUT = -1


class VulnerabilitiesProvider:
    """
    This is an abstraction for providing answers to any and all vulnerability related questions in the system.
    It encapsulates a scanner for finding vulnerabilities in an image and an optional cache manager to cache the resulting reports.
    In addition the provider support queries for vulnerabilities and aggregating vulnerability data across images
    """

    __scanner__ = None
    __cache_manager__ = None

    def load_image(self, **kwargs):
        """
        Ingress the image and compute the vulnerability matches. To be used in the load image path to prime the matches
        """
        raise NotImplementedError()

    def get_image_vulnerabilities(self, **kwargs):
        """
        Returns a vulnerabilities report for the image. To be used to fetch vulnerabilities for an already loaded image
        """
        raise NotImplementedError()

    def get_vulnerabilities(self, **kwargs):
        """
        Query the vulnerabilities database (not matched vulnerabilities) with filters
        """
        raise NotImplementedError()

    def get_images_by_vulnerability(self, **kwargs):
        """
        Query the image set impacted by a specific vulnerability
        """
        raise NotImplementedError()


class LegacyProvider(VulnerabilitiesProvider):
    """
    The legacy provider is based on image data loaded into the policy-engine database.
    For backwards compatibility there is no cache manager
    """

    __scanner__ = LegacyScanner
    __cache_manager__ = None

    def load_image(self, image: Image, db_session, cache=False):
        # initialize the scanner
        scanner = self.__scanner__()

        # flush existing matches, recompute matches and add them to session
        scanner.flush_and_recompute_vulnerabilities(image, db_session=db_session)

    def get_image_vulnerabilities(
        self,
        image: Image,
        db_session,
        vendor_only: bool = True,
        force_refresh: bool = False,
        cache: bool = True,
    ):
        # select the nvd class once and be done
        _nvd_cls, _cpe_cls = select_nvd_classes(db_session)

        # initialize the scanner
        scanner = self.__scanner__()

        user_id = image.user_id
        image_id = image.id

        results = []

        if force_refresh:
            log.info(
                "Forcing refresh of vulnerabilities for {}/{}".format(user_id, image_id)
            )
            try:
                scanner.flush_and_recompute_vulnerabilities(
                    image, db_session=db_session
                )
                db_session.commit()
            except Exception as e:
                log.exception(
                    "Error refreshing cve matches for image {}/{}".format(
                        user_id, image_id
                    )
                )
                db_session.rollback()
                return make_response_error(
                    "Error refreshing vulnerability listing for image.",
                    in_httpcode=500,
                )

            db_session = get_session()
            db_session.refresh(image)

        with timer("Image vulnerability primary lookup", log_level="debug"):
            vulns = scanner.get_vulnerabilities(image)

        # Has vulnerabilities?
        warns = []
        if not vulns:
            vulns = []
            ns = DistroNamespace.for_obj(image)
            if not have_vulnerabilities_for(ns):
                warns = [
                    "No vulnerability data available for image distro: {}".format(
                        ns.namespace_name
                    )
                ]

        rows = []
        with timer("Image vulnerability nvd metadata merge", log_level="debug"):
            vulns = merge_nvd_metadata_image_packages(
                db_session, vulns, _nvd_cls, _cpe_cls
            )

        with timer("Image vulnerability output formatting", log_level="debug"):
            for vuln, nvd_records in vulns:
                fixed_artifact = vuln.fixed_artifact()

                # Skip the vulnerability if the vendor_only flag is set to True and the issue won't be addressed by the vendor
                if vendor_only and vuln.fix_has_no_advisory(fixed_in=fixed_artifact):
                    continue

                nvd_scores = [
                    self._make_cvss_score(score)
                    for nvd_record in nvd_records
                    for score in nvd_record.get_cvss_scores_nvd()
                ]

                results.append(
                    VulnerabilityMatch(
                        vulnerability=VulnerabilityModel(
                            vulnerability_id=vuln.vulnerability_id,
                            description="NA",
                            severity=vuln.vulnerability.severity,
                            link=vuln.vulnerability.link,
                            feed="vulnerabilities",
                            feed_group=vuln.vulnerability.namespace_name,
                            cvss_scores_nvd=nvd_scores,
                            cvss_scores_vendor=[],
                            created_at=vuln.vulnerability.created_at,
                            last_modified=vuln.vulnerability.updated_at,
                        ),
                        artifact=Artifact(
                            name=vuln.pkg_name,
                            version=vuln.package.fullversion,
                            pkg_type=vuln.pkg_type,
                            pkg_path=vuln.pkg_path,
                            cpe="None",
                            cpe23="None",
                        ),
                        fixes=[
                            FixedArtifact(
                                version=str(vuln.fixed_in(fixed_in=fixed_artifact)),
                                wont_fix=vuln.fix_has_no_advisory(
                                    fixed_in=fixed_artifact
                                ),
                                observed_at=fixed_artifact.fix_observed_at
                                if fixed_artifact
                                else None,
                            )
                        ],
                        match=Match(detected_at=vuln.created_at),
                    )
                )

        # TODO move dedup here so api doesn't have to
        # cpe_vuln_listing = []
        try:
            with timer("Image vulnerabilities cpe matches", log_level="debug"):
                all_cpe_matches = scanner.get_cpe_vulnerabilities(
                    image, _nvd_cls, _cpe_cls
                )

                if not all_cpe_matches:
                    all_cpe_matches = []

                api_endpoint = self._get_api_endpoint()

                for image_cpe, vulnerability_cpe in all_cpe_matches:
                    link = vulnerability_cpe.parent.link
                    if not link:
                        link = "{}/query/vulnerabilities?id={}".format(
                            api_endpoint, vulnerability_cpe.vulnerability_id
                        )

                    nvd_scores = [
                        self._make_cvss_score(score)
                        for score in vulnerability_cpe.parent.get_cvss_scores_nvd()
                    ]

                    vendor_scores = [
                        self._make_cvss_score(score)
                        for score in vulnerability_cpe.parent.get_cvss_scores_vendor()
                    ]

                    results.append(
                        VulnerabilityMatch(
                            vulnerability=VulnerabilityModel(
                                vulnerability_id=vulnerability_cpe.parent.normalized_id,
                                description="NA",
                                severity=vulnerability_cpe.parent.severity,
                                link=link,
                                feed=vulnerability_cpe.feed_name,
                                feed_group=vulnerability_cpe.namespace_name,
                                cvss_scores_nvd=nvd_scores,
                                cvss_scores_vendor=vendor_scores,
                                created_at=vulnerability_cpe.parent.created_at,
                                last_modified=vulnerability_cpe.parent.updated_at,
                            ),
                            artifact=Artifact(
                                name=image_cpe.name,
                                version=image_cpe.version,
                                pkg_type=image_cpe.pkg_type,
                                pkg_path=image_cpe.pkg_path,
                                cpe=image_cpe.get_cpestring(),
                                cpe23=image_cpe.get_cpe23string(),
                            ),
                            fixes=[
                                FixedArtifact(
                                    version=item,
                                    wont_fix=False,
                                    observed_at=vulnerability_cpe.created_at,
                                )
                                for item in vulnerability_cpe.get_fixed_in()
                            ],
                            # using vulnerability created_at to indicate the match timestamp for now
                            match=Match(detected_at=vulnerability_cpe.created_at),
                        )
                    )
        except Exception as err:
            log.exception("could not fetch CPE matches")

        import uuid

        return ImageVulnerabilitiesReport(
            account_id=image.user_id,
            image_id=image_id,
            results=results,
            metadata=VulnerabilitiesReportMetadata(
                generated_at=datetime.datetime.utcnow(),
                uuid=str(uuid.uuid4()),
                generated_by=self._get_provider_metadata(),
            ),
            problems=[],
        )

    def get_vulnerabilities(
        self, ids, package_name_filter, package_version_filter, namespace, db_session
    ):
        """
        Return vulnerability records with the matched criteria from the feed data.
        Copy pasted query_vulnerabilities() from synchronous_operations.py

        TODO use "with timer" for timing blocks
        TODO define message models use concretely objects instead of dictionaries

        :param ids: single string or list of string ids
        :param package_name_filter: string name to filter vulns by in the affected package list
        :param package_version_filter: version for corresponding package to filter by
        :param namespace: string or list of strings to filter namespaces by
        :param db_session: active db session to use
        :return: list of dicts
        """
        return_object = []

        return_el_template = {
            "id": None,
            "namespace": None,
            "severity": None,
            "link": None,
            "affected_packages": None,
            "description": None,
            "references": None,
            "nvd_data": None,
            "vendor_data": None,
        }

        # order_by ascending timestamp will result in dedup hash having only the latest information stored for return, if there are duplicate records for NVD
        (_nvd_cls, _cpe_cls) = select_nvd_classes(db_session)

        # Set the relationship loader for use with the queries
        loader = orm.selectinload

        # Always fetch any matching nvd records, even if namespace doesn't match, since they are used for the cvss data
        qry = (
            db_session.query(_nvd_cls)
            .options(loader(_nvd_cls.vulnerable_cpes))
            .filter(_nvd_cls.name.in_(ids))
            .order_by(asc(_nvd_cls.created_at))
        )

        t1 = time.time()
        nvd_vulnerabilities = qry.all()
        nvd_vulnerabilities.extend(
            db_session.query(VulnDBMetadata)
            .options(loader(VulnDBMetadata.cpes))
            .filter(VulnDBMetadata.name.in_(ids))
            .order_by(asc(VulnDBMetadata.created_at))
            .all()
        )

        log.spew("Vuln query 1 timing: {}".format(time.time() - t1))

        api_endpoint = self._get_api_endpoint()

        if not namespace or ("nvdv2:cves" in namespace):
            dedupped_return_hash = {}
            t1 = time.time()

            for vulnerability in nvd_vulnerabilities:
                link = vulnerability.link
                if not link:
                    link = "{}/query/vulnerabilities?id={}".format(
                        api_endpoint, vulnerability.name
                    )

                namespace_el = {}
                namespace_el.update(return_el_template)
                namespace_el["id"] = vulnerability.name
                namespace_el["namespace"] = vulnerability.namespace_name
                namespace_el["severity"] = vulnerability.severity
                namespace_el["link"] = link
                namespace_el["affected_packages"] = []
                namespace_el["description"] = vulnerability.description
                namespace_el["references"] = vulnerability.references
                namespace_el["nvd_data"] = vulnerability.get_cvss_data_nvd()
                namespace_el["vendor_data"] = vulnerability.get_cvss_data_vendor()

                for v_pkg in vulnerability.vulnerable_cpes:
                    if (
                        not package_name_filter or package_name_filter == v_pkg.name
                    ) and (
                        not package_version_filter
                        or package_version_filter == v_pkg.version
                    ):
                        pkg_el = {
                            "name": v_pkg.name,
                            "version": v_pkg.version,
                            "type": "*",
                        }
                        namespace_el["affected_packages"].append(pkg_el)

                if not package_name_filter or (
                    package_name_filter and namespace_el["affected_packages"]
                ):
                    dedupped_return_hash[namespace_el["id"]] = namespace_el

            log.spew("Vuln merge took {}".format(time.time() - t1))

            return_object.extend(list(dedupped_return_hash.values()))

        if namespace == ["nvdv2:cves"]:
            # Skip if requested was 'nvd'
            vulnerabilities = []
        else:
            t1 = time.time()

            qry = (
                db_session.query(Vulnerability)
                .options(loader(Vulnerability.fixed_in))
                .filter(Vulnerability.id.in_(ids))
            )

            if namespace:
                if type(namespace) == str:
                    namespace = [namespace]

                qry = qry.filter(Vulnerability.namespace_name.in_(namespace))

            vulnerabilities = qry.all()

            log.spew("Vuln query 2 timing: {}".format(time.time() - t1))

        if vulnerabilities:
            log.spew("Merging nvd data into the vulns")
            t1 = time.time()
            merged_vulns = merge_nvd_metadata(
                db_session,
                vulnerabilities,
                _nvd_cls,
                _cpe_cls,
                already_loaded_nvds=nvd_vulnerabilities,
            )
            log.spew("Vuln nvd query 2 timing: {}".format(time.time() - t1))

            for entry in merged_vulns:
                vulnerability = entry[0]
                nvds = entry[1]
                namespace_el = {}
                namespace_el.update(return_el_template)
                namespace_el["id"] = vulnerability.id
                namespace_el["namespace"] = vulnerability.namespace_name
                namespace_el["severity"] = vulnerability.severity
                namespace_el["link"] = vulnerability.link
                namespace_el["affected_packages"] = []

                namespace_el["nvd_data"] = []
                namespace_el["vendor_data"] = []

                for nvd_record in nvds:
                    namespace_el["nvd_data"].extend(nvd_record.get_cvss_data_nvd())

                for v_pkg in vulnerability.fixed_in:
                    if (
                        not package_name_filter or package_name_filter == v_pkg.name
                    ) and (
                        not package_version_filter
                        or package_version_filter == v_pkg.version
                    ):
                        pkg_el = {
                            "name": v_pkg.name,
                            "version": v_pkg.version,
                            "type": v_pkg.version_format,
                        }
                        if not v_pkg.version or v_pkg.version.lower() == "none":
                            pkg_el["version"] = "*"

                        namespace_el["affected_packages"].append(pkg_el)

                for v_pkg in vulnerability.vulnerable_in:
                    if (
                        not package_name_filter or package_name_filter == v_pkg.name
                    ) and (
                        not package_version_filter
                        or package_version_filter == v_pkg.version
                    ):
                        pkg_el = {
                            "name": v_pkg.name,
                            "version": v_pkg.version,
                            "type": v_pkg.version_format,
                        }
                        if not v_pkg.version or v_pkg.version.lower() == "none":
                            pkg_el["version"] = "*"

                        namespace_el["affected_packages"].append(pkg_el)

                if not package_name_filter or (
                    package_name_filter and namespace_el["affected_packages"]
                ):
                    return_object.append(namespace_el)

        return return_object

    def get_images_by_vulnerability(
        self,
        user_id,
        id,
        severity_filter,
        namespace_filter,
        affected_package_filter,
        vendor_only,
        db_session,
    ):
        """
        Return image with nested package records that match the filter criteria

        Copy pasted query_images_by_vulnerability() from synchronous_operations.py

        TODO use "with timer" for timing blocks
        TODO define message models use concretely objects instead of dictionaries
        """

        ret_hash = {}
        pkg_hash = {}
        advisory_cache = {}

        start = time.time()
        image_package_matches = []
        image_cpe_matches = []
        image_cpe_vlndb_matches = []

        (_nvd_cls, _cpe_cls) = select_nvd_classes(db_session)

        ipm_query = (
            db_session.query(ImagePackageVulnerability)
            .filter(ImagePackageVulnerability.vulnerability_id == id)
            .filter(ImagePackageVulnerability.pkg_user_id == user_id)
        )
        icm_query = (
            db_session.query(ImageCpe, _cpe_cls)
            .filter(_cpe_cls.vulnerability_id == id)
            .filter(func.lower(ImageCpe.name) == _cpe_cls.name)
            .filter(ImageCpe.image_user_id == user_id)
            .filter(ImageCpe.version == _cpe_cls.version)
        )
        icm_vulndb_query = db_session.query(ImageCpe, VulnDBCpe).filter(
            VulnDBCpe.vulnerability_id == id,
            func.lower(ImageCpe.name) == VulnDBCpe.name,
            ImageCpe.image_user_id == user_id,
            ImageCpe.version == VulnDBCpe.version,
            VulnDBCpe.is_affected.is_(True),
        )

        if severity_filter:
            ipm_query = ipm_query.filter(
                ImagePackageVulnerability.vulnerability.has(severity=severity_filter)
            )
            icm_query = icm_query.filter(
                _cpe_cls.parent.has(severity=severity_filter)
            )  # might be slower than join
            icm_vulndb_query = icm_vulndb_query.filter(
                _cpe_cls.parent.has(severity=severity_filter)
            )  # might be slower than join
        if namespace_filter:
            ipm_query = ipm_query.filter(
                ImagePackageVulnerability.vulnerability_namespace_name
                == namespace_filter
            )
            icm_query = icm_query.filter(_cpe_cls.namespace_name == namespace_filter)
            icm_vulndb_query = icm_vulndb_query.filter(
                VulnDBCpe.namespace_name == namespace_filter
            )
        if affected_package_filter:
            ipm_query = ipm_query.filter(
                ImagePackageVulnerability.pkg_name == affected_package_filter
            )
            icm_query = icm_query.filter(
                func.lower(ImageCpe.name) == func.lower(affected_package_filter)
            )
            icm_vulndb_query = icm_vulndb_query.filter(
                func.lower(ImageCpe.name) == func.lower(affected_package_filter)
            )

        image_package_matches = ipm_query  # .all()
        image_cpe_matches = icm_query  # .all()
        image_cpe_vlndb_matches = icm_vulndb_query

        log.debug("QUERY TIME: {}".format(time.time() - start))

        start = time.time()
        if image_package_matches or image_cpe_matches or image_cpe_vlndb_matches:
            imageId_to_record = get_imageId_to_record(user_id, dbsession=db_session)

            start = time.time()
            for image in image_package_matches:
                if vendor_only and self._check_no_advisory(image, advisory_cache):
                    continue

                imageId = image.pkg_image_id
                if imageId not in ret_hash:
                    ret_hash[imageId] = {
                        "image": imageId_to_record.get(imageId, {}),
                        "vulnerable_packages": [],
                    }
                    pkg_hash[imageId] = {}

                pkg_el = {
                    "name": image.pkg_name,
                    "version": image.pkg_version,
                    "type": image.pkg_type,
                    "namespace": image.vulnerability_namespace_name,
                    "severity": image.vulnerability.severity,
                }

                ret_hash[imageId]["vulnerable_packages"].append(pkg_el)
            log.debug("IMAGEOSPKG TIME: {}".format(time.time() - start))

            for cpe_matches in [image_cpe_matches, image_cpe_vlndb_matches]:
                start = time.time()
                for image_cpe, vulnerability_cpe in cpe_matches:
                    imageId = image_cpe.image_id
                    if imageId not in ret_hash:
                        ret_hash[imageId] = {
                            "image": imageId_to_record.get(imageId, {}),
                            "vulnerable_packages": [],
                        }
                        pkg_hash[imageId] = {}
                    pkg_el = {
                        "name": image_cpe.name,
                        "version": image_cpe.version,
                        "type": image_cpe.pkg_type,
                        "namespace": "{}".format(vulnerability_cpe.namespace_name),
                        "severity": "{}".format(vulnerability_cpe.parent.severity),
                    }
                    phash = hashlib.sha256(
                        json.dumps(pkg_el).encode("utf-8")
                    ).hexdigest()
                    if not pkg_hash[imageId].get(phash, False):
                        ret_hash[imageId]["vulnerable_packages"].append(pkg_el)
                    pkg_hash[imageId][phash] = True

                log.debug("IMAGECPEPKG TIME: {}".format(time.time() - start))

        start = time.time()
        vulnerable_images = list(ret_hash.values())
        return_object = {"vulnerable_images": vulnerable_images}
        log.debug("RESP TIME: {}".format(time.time() - start))

        return return_object

    def _get_provider_metadata(self):
        return {
            "name": self.__class__.__name__,
            "version": version.version,
            "database_version": version.db_version,
        }

    @staticmethod
    def _check_no_advisory(img_pkg_vuln, advisory_cache):
        """
        Caches and returns vendor advisory or "won't fix" for a vulnerability.
        Cache is a dictionary with ImagePackageVulnerability hash mapped to "won't fix"

        Copied check_no_advisory() from synchronous_operations.py
        """
        phash = hashlib.sha256(
            json.dumps(
                [
                    img_pkg_vuln.pkg_name,
                    img_pkg_vuln.pkg_version,
                    img_pkg_vuln.vulnerability_namespace_name,
                ]
            ).encode("utf-8")
        ).hexdigest()
        if phash not in advisory_cache:
            advisory_cache[phash] = img_pkg_vuln.fix_has_no_advisory()

        return advisory_cache.get(phash)

    @staticmethod
    def _make_cvss_score(score):
        """
        Utility function for creating a cvss score object from a dictionary
        """
        return CvssCombined(
            id=score.get("id"),
            cvss_v2=CvssScore.CvssScoreV1Schema().make(data=score.get("cvss_v2")),
            cvss_v3=CvssScore.CvssScoreV1Schema().make(data=score.get("cvss_v3")),
        )

    @staticmethod
    def _get_api_endpoint():
        """
        Utility function for fetching the url to external api
        """
        try:
            return get_service_endpoint("apiext").strip("/")
        except:
            log.warn(
                "Could not find valid apiext endpoint for links so will use policy engine endpoint instead"
            )
            try:
                return get_service_endpoint("policy_engine").strip("/")
            except:
                log.warn(
                    "No policy engine endpoint found either, using default but invalid url"
                )
                return "http://<valid endpoint not found>"


default_type = LegacyProvider


def get_vulnerabilities_provider():
    return default_type()
