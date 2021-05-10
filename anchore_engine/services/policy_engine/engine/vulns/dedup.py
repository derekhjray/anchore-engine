from collections import namedtuple
from typing import List

from anchore_engine.services.policy_engine.api.models import VulnerabilityMatch
from anchore_engine.subsys import logger


class FeedGroupRank:
    """
    Feed groups ranked by an integer value. Rank defaults to pre-defined value if the group is not not explicitly ranked
    """

    __ranks__ = {"nvdv2": 1, "github": 10}
    __default__ = 100

    @classmethod
    def get(cls, feed_group):
        group_prefix = feed_group.split(":", 1)[0]

        return cls.__ranks__.get(group_prefix, cls.__default__)


class DedupProcessor:
    """
    A mechanism for finding and removing duplicates from a list of vulnerability matches

    Employs a configurable strategy to compute the rank of a given record and picks the record with the highest rank when there are duplicates
    """

    IdentityTuple = namedtuple(
        "IdentityTuple", ["vuln_id", "pkg_name", "pkg_version", "pkg_type", "pkg_path"]
    )
    VulnerabilityRankTuple = namedtuple(
        "VulnerabilityRankTuple",
        [
            "vuln_id",
            "vuln_namespace",
            "pkg_name",
            "pkg_version",
            "pkg_type",
            "pkg_path",
            "rank",
        ],
    )
    VulnerabilityRankMatchTuple = namedtuple(
        "VulnerabilityRankMatchTuple", ["vulnerability_rank_tuple", "match"]
    )

    __ranking_strategy__ = FeedGroupRank

    @classmethod
    def _get_vulnerability_rank_tuple(
        cls, vulnerability_match: VulnerabilityMatch
    ) -> VulnerabilityRankTuple:
        """
        Helper function for creating VulnTuple from a VulnerabilityMatch object
        """
        return cls.VulnerabilityRankTuple(
            vulnerability_match.vulnerability.vulnerability_id,
            vulnerability_match.vulnerability.feed_group,
            vulnerability_match.artifact.name,
            vulnerability_match.artifact.version,
            vulnerability_match.artifact.pkg_type,
            vulnerability_match.artifact.pkg_path,
            cls.__ranking_strategy__.get(vulnerability_match.vulnerability.feed_group),
        )

    @classmethod
    def _get_identity_tuple(
        cls, vulnerability_id: str, vulnerability_match: VulnerabilityMatch
    ) -> IdentityTuple:
        """
        Helper function for creating NVDTuple from a VulnerabilityMatch object
        """
        return cls.IdentityTuple(
            vulnerability_id,
            vulnerability_match.artifact.name,
            vulnerability_match.artifact.version,
            vulnerability_match.artifact.pkg_type,
            vulnerability_match.artifact.pkg_path,
        )

    @classmethod
    def execute(
        cls, vulnerability_matches: List[VulnerabilityMatch]
    ) -> List[VulnerabilityMatch]:
        """
        Finds duplicate records (for a specific definition of duplicate) in the provided list of vulnerability matches.
        Uses a defined strategy to rank such records and selects the highest ranking record to de-duplicate.

        Matches are considered duplicate when they affect the same package - identified by its name and location, and
        seemingly refer to the same vulnerability. The latter is explained by the following examples

        1. Match A contains vulnerability x with an nvd reference to vulnerability y in namespace z.
        Match B contains vulnerability y in the nvdv2 namespace. Matches A and B are duplicates.
        This is observed in feeds that don't use CVE IDs such as GHSA, ELSA, ALAS etc
        2. Match A contains vulnerability x in namespace y. Match B contains vulnerability x in namespace z.
        Matches A and B are duplicates.
        """

        if not vulnerability_matches:
            return []

        # de-dup is centered around nvd references. so pivot the data set first and create an identity
        # using nvd identifiers when available. map this nvd identity to the vulnerability
        identity_map = dict()

        for vuln_match in vulnerability_matches:
            # generate the rank tuple first
            vuln_rank_tuple = cls._get_vulnerability_rank_tuple(vuln_match)

            if vuln_match.vulnerability.cvss_scores_nvd:
                # generate identity tuples using the nvd refs
                identity_tuples = [
                    cls._get_identity_tuple(nvd_score.id, vuln_match)
                    for nvd_score in vuln_match.vulnerability.cvss_scores_nvd
                ]
            else:
                # no nvd refs, generate the identity tuple using the vulnerability id
                identity_tuples = [
                    cls._get_identity_tuple(
                        vuln_match.vulnerability.vulnerability_id, vuln_match
                    )
                ]

            # now map each identity to the vulnerability. Rank and select as you go
            for identity_tuple in identity_tuples:
                if identity_tuple in identity_map:
                    # identity is already mapped to a vulnerability, get the mapped vulnerability and compare ranks
                    existing = identity_map.get(identity_tuple)
                    if vuln_rank_tuple.rank > existing.vulnerability_rank_tuple.rank:
                        # current vulnerability rank is higher than existing, re-map
                        logger.debug(
                            "De-dup detected %s is ranked higher than %s. Replacing"
                            % (vuln_rank_tuple, existing.vulnerability_rank_tuple)
                        )
                        identity_map[identity_tuple] = cls.VulnerabilityRankMatchTuple(
                            vuln_rank_tuple, vuln_match
                        )
                else:
                    # identity encountered first time, create a mapping to the vulnerability
                    identity_map[identity_tuple] = cls.VulnerabilityRankMatchTuple(
                        vuln_rank_tuple, vuln_match
                    )

        # At this point identity_map contains unique nvd identities, each mapped to a vulnerability.
        # mapped values may repeat because of the initial data pivot. So pivot back and gather unique vulnerabilities
        final_vulnerability_rank_tuples = set()
        final_vulnerability_matches = []
        for item in identity_map.values():
            if item.vulnerability_rank_tuple not in final_vulnerability_rank_tuples:
                final_vulnerability_rank_tuples.add(item.vulnerability_rank_tuple)
                final_vulnerability_matches.append(item.match)

        return final_vulnerability_matches
