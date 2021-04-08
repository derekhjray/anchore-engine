import logging
import os

import pytest

import tests.functional.services.policy_engine.utils.api as policy_engine_api
from tests.functional.services.policy_engine.conftest import FEEDS_DATA_PATH_PREFIX
from tests.functional.services.utils import http_utils


class TestFeedSync:
    @classmethod
    def _find_by_name(cls, records, name):
        """
        From a list of objects/dictionaries, selects first index with matching name. Returns None if nothing is found
        :param records: list of objects or dictionaries that are expected to have 'name' attr
        :type records: list
        :return: dict with matching name or 'None' if nothing found
        :rtype: Union[dict, None]
        """
        for record in records:
            if record["name"] == name:
                return record
        return None

    @classmethod
    def _get_vuln_ids(cls, expected_vulns):
        """
        From a list of expected vulns taken from feeds service, find corresponding vulnerability ids for querying anchore
        :param expected_vulns: list of records in group from feed
        :type expected_vulns: list
        :return: list of vulnerabilitiy_ids as they would be stored in anchore
        :rtype: list
        """
        vuln_ids = []
        for vuln in expected_vulns:
            # GHSA
            if "Advisory" in vuln:
                vuln_ids.append(vuln["Advisory"]["ghsaId"])
            # NVDV2
            if "cve" in vuln:
                vuln_ids.append(vuln["cve"]["CVE_data_meta"]["ID"])
            # Vulnerabilities
            if "Vulnerability" in vuln:
                # GHSA also has "Vulnerabilities", but value is empty object
                if "Name" in vuln["Vulnerability"]:
                    vuln_ids.append(vuln["Vulnerability"]["Name"])
        return vuln_ids

    @pytest.fixture(scope="class")
    def sync_feeds(self, clear_vuln_data_temporary):
        """
        Uses clear database fixture and calls a feed sync. Scoped to occur only once for the class rather than each test
        """
        return policy_engine_api.feeds.feeds_sync()

    def test_feeds_sync_schema(self, sync_feeds, schema_validator):
        feed_sync_resp = sync_feeds
        feeds_sync_schema_validator = schema_validator("feeds_sync.schema.json")
        is_valid: bool = feeds_sync_schema_validator.is_valid(feed_sync_resp.body)
        if not is_valid:
            for err in feeds_sync_schema_validator.iter_errors(feed_sync_resp.body):
                logging.error(err)
        assert is_valid

    def test_feeds_get_schema(self, sync_feeds, schema_validator):
        feeds_get_resp = policy_engine_api.feeds.get_feeds(True)
        validator = schema_validator("feeds_get.schema.json")
        is_valid: bool = validator.is_valid(feeds_get_resp.body)
        if not is_valid:
            for err in validator.iter_errors(feeds_get_resp.body):
                logging.error(err)
        assert is_valid

    def test_expected_feed_sync(self, expected_content, sync_feeds):
        feed_sync_resp = policy_engine_api.feeds.feeds_sync()
        assert feed_sync_resp == http_utils.APIResponse(200)
        for feed in feed_sync_resp.body:
            assert feed["status"] == "success"

        feeds_get_resp = policy_engine_api.feeds.get_feeds(True)

        # get feeds index file
        expected_feeds = expected_content(
            os.path.join(FEEDS_DATA_PATH_PREFIX, "index")
        )["feeds"]

        assert len(feeds_get_resp.body) == len(expected_feeds)

        for expected_feed in expected_feeds:
            # assert that expected feed is present in found list and enabled
            actual_feed = self._find_by_name(feeds_get_resp.body, expected_feed["name"])
            assert not isinstance(actual_feed, type(None))
            assert actual_feed["enabled"]

            expected_groups = expected_content(
                os.path.join(FEEDS_DATA_PATH_PREFIX, expected_feed["name"], "index")
            )["groups"]

            # iterate over expected groups and verify data
            for expected_group in expected_groups:
                actual_group = self._find_by_name(
                    actual_feed["groups"], expected_group["name"]
                )
                assert actual_group
                assert actual_group["enabled"]

                # get expected cves and query to verify they are present
                expected_vulns = expected_content(
                    os.path.join(
                        FEEDS_DATA_PATH_PREFIX,
                        expected_feed["name"],
                        expected_group["name"],
                    )
                )["data"]
                assert actual_group["record_count"] == len(expected_vulns)

                vuln_ids = self._get_vuln_ids(expected_vulns)

                vuln_response = (
                    policy_engine_api.query_vulnerabilities.get_vulnerabilities(
                        vuln_ids, namespace=expected_group["name"]
                    )
                )

                assert len(vuln_response.body) == len(expected_vulns)
                assert len(set([x["id"] for x in vuln_response.body])) == len(
                    expected_vulns
                )
