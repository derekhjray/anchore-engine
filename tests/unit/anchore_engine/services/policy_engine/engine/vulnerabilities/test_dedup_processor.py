import pytest

from anchore_engine.services.policy_engine.api.models import (
    VulnerabilityMatch,
    Vulnerability,
    Artifact,
    CvssCombined,
)
from anchore_engine.services.policy_engine.engine.vulns.dedup import (
    DedupProcessor,
    FeedGroupRank,
)


class TestFeedGroupRank:
    @pytest.mark.parametrize(
        "test_group, expected_rank",
        [
            pytest.param("nvdv2:cves", 1, id="nvdv2"),
            pytest.param("github:java", 10, id="github"),
            pytest.param("alpine:3.9", 100, id="os-distro"),
            pytest.param("foobar", 100, id="random"),
        ],
    )
    def test_get(self, test_group, expected_rank):
        assert FeedGroupRank.get(test_group) == expected_rank


class TestDedupProcessor:
    @pytest.mark.parametrize(
        "test_input, expected_index",
        [
            pytest.param(
                [
                    Vulnerability(
                        feed="vulnerabilities",
                        feed_group="nvdv2:cves",
                        vulnerability_id="CVE-2019-12904",
                        cvss_scores_nvd=[CvssCombined(id="CVE-2019-12904")],
                    ),
                    Vulnerability(
                        feed="vulnerabilities",
                        feed_group="ubuntu:20.04",
                        vulnerability_id="CVE-2019-12904",
                        cvss_scores_nvd=[CvssCombined(id="CVE-2019-12904")],
                    ),
                ],
                1,
                id="different-namespaces",
            ),
            pytest.param(
                [
                    Vulnerability(
                        feed="vulnerabilities",
                        feed_group="nvdv2:cves",
                        vulnerability_id="CVE-2019-12904",
                        cvss_scores_nvd=[CvssCombined(id="CVE-2019-12904")],
                    ),
                    Vulnerability(
                        feed="vulnerabilities",
                        feed_group="github:java",
                        vulnerability_id="GHSA-foobar",
                        cvss_scores_nvd=[CvssCombined(id="CVE-2019-12904")],
                    ),
                ],
                1,
                id="different-identifiers",
            ),
            pytest.param(
                [
                    Vulnerability(
                        feed="vulnerabilities",
                        feed_group="github:java",
                        vulnerability_id="GHSA-foobar",
                        cvss_scores_nvd=[CvssCombined(id="CVE-2019-12904")],
                    ),
                    Vulnerability(
                        feed="vulnerabilities",
                        feed_group="ubuntu:20.04",
                        vulnerability_id="CVE-2019-12904",
                        cvss_scores_nvd=[CvssCombined(id="CVE-2019-12904")],
                    ),
                ],
                1,
                id="non-nvd-namespaces",
            ),
            pytest.param(
                [
                    Vulnerability(
                        feed="vulnerabilities",
                        feed_group="nvdv2:cves",
                        vulnerability_id="CVE-2019-12904",
                        cvss_scores_nvd=[CvssCombined(id="CVE-2019-12904")],
                    ),
                    Vulnerability(
                        feed="vulnerabilities",
                        feed_group="ubuntu:20.04",
                        vulnerability_id="CVE-2019-12904",
                        cvss_scores_nvd=[],
                    ),
                ],
                1,
                id="no-nvd-refs",
            ),
            pytest.param(
                [
                    Vulnerability(
                        feed="vulnerabilities",
                        feed_group="nvdv2:cves",
                        vulnerability_id="CVE-2019-12904",
                        cvss_scores_nvd=[CvssCombined(id="CVE-2019-12904")],
                    ),
                    Vulnerability(
                        feed="vulnerabilities",
                        feed_group="nvdv2:cves",
                        vulnerability_id="CVE-2019-12904",
                        cvss_scores_nvd=[CvssCombined(id="CVE-2019-12904")],
                    ),
                    Vulnerability(
                        feed="vulnerabilities",
                        feed_group="github:java",
                        vulnerability_id="GHSA-foobar",
                        cvss_scores_nvd=[
                            CvssCombined(id="CVE-2019-12904"),
                            CvssCombined(id="CVE-2019-12345"),
                        ],
                    ),
                ],
                2,
                id="multiple-nvd-refs",
            ),
        ],
    )
    def test_execute(self, test_input, expected_index):
        matches_input = [
            VulnerabilityMatch(
                artifact=Artifact(
                    name="blah",
                    pkg_path="/usr/local/java/blah",
                    pkg_type="java",
                    version="1.2.3maven",
                ),
                vulnerability=item,
            )
            for item in test_input
        ]

        results = DedupProcessor.execute(matches_input)
        assert len(results) == 1

        actual = results[0].vulnerability
        expected = test_input[expected_index]
        assert actual.vulnerability_id == expected.vulnerability_id
        assert actual.feed_group == expected.feed_group

    @pytest.mark.parametrize("count", [1, 2, 3, 4, 5])
    def test_execute_absolute_duplicates(self, count):
        a = VulnerabilityMatch(
            artifact=Artifact(
                name="blah",
                pkg_path="/usr/local/java/blah",
                pkg_type="java",
                version="1.2.3maven",
            ),
            vulnerability=Vulnerability(
                feed="vulnerabilities",
                feed_group="whatever:hello",
                vulnerability_id="meh",
                cvss_scores_nvd=[CvssCombined(id="CVE-2019-12904")],
            ),
        )

        input_matches = [a for x in range(count)]

        results = DedupProcessor.execute(input_matches)
        assert len(results) == 1

    @pytest.mark.parametrize(
        "test_input",
        [pytest.param([], id="empty-list"), pytest.param(None, id="none")],
    )
    def test_execute_invalid_input(self, test_input):
        assert DedupProcessor.execute(test_input) == list()
