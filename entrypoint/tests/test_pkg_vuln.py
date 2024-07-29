import json
import os
import unittest

from entrypoint import pkg_vuln


def read_test_file(file: str) -> str:
    file_contents = ""
    with open(file, "r") as f:
        file_contents = f.read()
    return file_contents


class ConverterTestCase(unittest.TestCase):

    def test_get_pkg_vulns(self):
        test_file = "tests/test_data/artifacts/containers/dockerfile_checks/inspector-scan-cdx.json"
        inspector_scan = get_scan_body(test_file)
        vulns_dict = inspector_scan["vulnerabilities"]
        vulns = pkg_vuln.get_pkg_vulns(vulns_dict)
        self.assertTrue(vulns is not None)
        self.assertTrue(len(vulns) > 0)
        for v in vulns:
            self.assertTrue("IN-DOCKERFILE" not in v["id"])
        return

    def test_parse_inspector_scan_result(self):
        test_file_base_dir = "tests/test_data/test_pkg_vuln/"
        tests = [
            {
                "name": "parse_inspector_scan_result should return non-empty vulnerability list",
                "test_file": os.path.join(test_file_base_dir, "inspector-scan-cdx.json"),
                "expected": [
                    pkg_vuln.Vulnerability(
                        vuln_id="CVE-2015-20109",
                        severity="medium",
                        severity_provider="NVD",
                        cvss_score="5.5",
                        published="2023-06-25T17:15:14Z",
                        modified="2023-07-31T19:15:15Z",
                        description="TEST_DESCRIPTION",
                        installed_ver=(
                            "pkg:golang/github.com/test-namespace/pkg-1@v0.4.0;"
                            + "pkg:golang/github.com/test-namespace/pkg-2@v2.4.0"
                        ),
                        fixed_ver="pkg-1;pkg-2",
                        pkg_path="/user/local/bin/pkg-1;/tmp/pkg-2",
                        epss_score="0.00044",
                        exploit_available="true",
                        exploit_last_seen="2024-05-17T05:13:34Z",
                        cwes="CWE-120",
                    ),
                    pkg_vuln.Vulnerability(
                        vuln_id="CVE-2000-20109",
                        severity="high",
                        severity_provider="MITRE",
                        cvss_score="9.1",
                        published="2023-06-25T17:15:14Z",
                        modified="2023-07-31T19:15:15Z",
                        description="TEST_DESCRIPTION",
                        installed_ver="pkg:golang/github.com/test-namespace/pkg-3@v3.0.0",
                        fixed_ver="pkg-3",
                        pkg_path="/tmp/pkg-3",
                        epss_score="0.00022",
                        exploit_available="true",
                        exploit_last_seen="2024-05-17T05:13:34Z",
                        cwes="CWE-120",
                    ),
                    pkg_vuln.Vulnerability(
                        vuln_id="CVE-2024-30000",
                        severity="untriaged",
                        severity_provider="AMAZON_INSPECTOR",
                        cvss_score="null",
                        published="2023-06-25T17:15:14Z",
                        modified="2023-07-31T19:15:15Z",
                        description="TEST_DESCRIPTION",
                        installed_ver="pkg:golang/github.com/test-namespace/pkg-5@v5.0.0",
                        fixed_ver="pkg-5",
                        pkg_path="/tmp/pkg-5",
                        epss_score="0.00022",
                        exploit_available="true",
                        exploit_last_seen="2024-05-17T05:13:34Z",
                        cwes="CWE-120",
                    ),
                ],
            },
            {
                "name": (
                    "parse_inspector_scan_result should return vulnerability with 'null' values"
                    + "when fields don't exist in the scan result"
                ),
                "test_file": os.path.join(test_file_base_dir, "inspector-scan-cdx-empty-vulnerability.json"),
                "expected": [
                    pkg_vuln.Vulnerability(
                        vuln_id="vulnerability-id",
                        severity=pkg_vuln.CvssSeverity.UNTRIAGED,
                        severity_provider=pkg_vuln.CvssSourceProvider.DEFAULT_PROVIDER,
                        cvss_score=pkg_vuln.NULL_STR,
                        published=pkg_vuln.NULL_STR,
                        modified=pkg_vuln.NULL_STR,
                        description=pkg_vuln.NULL_STR,
                        installed_ver=pkg_vuln.NULL_STR,
                        fixed_ver=pkg_vuln.NULL_STR,
                        pkg_path=pkg_vuln.NULL_STR,
                        epss_score=pkg_vuln.NULL_STR,
                        exploit_available=pkg_vuln.NULL_STR,
                        exploit_last_seen=pkg_vuln.NULL_STR,
                        cwes=pkg_vuln.NULL_STR,
                    )
                ],
            },
            {
                "name": "parse_inspector_scan_result should return vulnerability with purl for nested components",
                "test_file": os.path.join(test_file_base_dir, "inspector-scan-cdx-nested-components.json"),
                "expected": [
                    pkg_vuln.Vulnerability(
                        vuln_id="CVE-2015-20109",
                        severity="medium",
                        severity_provider="NVD",
                        cvss_score="5.5",
                        published="2023-06-25T17:15:14Z",
                        modified="2023-07-31T19:15:15Z",
                        description="TEST_DESCRIPTION",
                        installed_ver=(
                            "pkg:golang/github.com/test-namespace/pkg-2@v2.0.0;"
                            + "pkg:golang/github.com/test-namespace/pkg-3@v3.0.0"
                        ),
                        fixed_ver="pkg-2;pkg-3",
                        pkg_path="/tmp/pkg-2;/tmp/pkg-3",
                        epss_score="0.00044",
                        exploit_available="true",
                        exploit_last_seen="2024-05-17T05:13:34Z",
                        cwes="CWE-120",
                    )
                ],
            },
            {
                "name": "it should return empty list when components is null",
                "test_file": os.path.join(test_file_base_dir, "inspector-scan-cdx-no-components.json"),
                "expected": [],
            },
            {
                "name": "it should return empty list when vulnerabilities is null",
                "test_file": os.path.join(test_file_base_dir, "inspector-scan-cdx-no-vulnerabilities.json"),
                "expected": [],
            },
            {
                "name": "it should be empty list when inspector scan result only contains dockerfile findings",
                "test_file": os.path.join(test_file_base_dir, "inspector-scan-cdx-dockerfile-only.json"),
                "expected": [],
            },
        ]
        for test in tests:
            with self.subTest(test_case=test["name"]):
                with open(test["test_file"], "r") as f:
                    inspector_scan = json.load(f)
                    vulns = pkg_vuln.parse_inspector_scan_result(inspector_scan)
                    self.assertEqual(test["expected"], vulns)

    def test_get_cvss_rating(self):
        tests = [
            {
                "name": "NVD should take a priority over other providers",
                "ratings": [
                    {
                        "method": "CVSSv31",
                        "score": 7.2,
                        "severity": "high",
                        "source": {"name": "MITRE"},
                    },
                    {
                        "method": "CVSSv31",
                        "score": 5.3,
                        "severity": "medium",
                        "source": {"name": "NVD"},
                    },
                    {
                        "method": "other",
                        "score": 0.00051,
                        "severity": "none",
                        "source": {"name": "EPSS"},
                    },
                ],
                "expected": pkg_vuln.CvssRating("medium", "NVD", str(5.3)),
            },
            {
                "name": (
                    'score should be "null" and severity should be "untriaged" '
                    + 'when method is "other" and severity is "unknown" '
                ),
                "ratings": [
                    {
                        "method": "other",
                        "severity": "unknown",
                        "source": {"name": "AMAZON_INSPECTOR"},
                    },
                    {
                        "method": "other",
                        "score": 0.00051,
                        "severity": "none",
                        "source": {"name": "EPSS"},
                    },
                ],
                "expected": pkg_vuln.CvssRating("untriaged", "AMAZON_INSPECTOR", "null"),
            },
            {
                "name": 'rating should be "null" and severity is not provided when no CVSS rating is provided',
                "ratings": [
                    {
                        "method": "other",
                        "score": 0.00051,
                        "severity": "none",
                        "source": {"name": "EPSS"},
                    },
                ],
                "expected": pkg_vuln.CvssRating("untriaged", "NVD", "null"),
            },
        ]
        for test in tests:
            with self.subTest(msg=test["name"]):
                rating = pkg_vuln.get_cvss_rating(test["ratings"], pkg_vuln.Vulnerability())
                self.assertEqual(test["expected"], rating)


def get_scan_body(test_file):
    # test_file = "tests/test_data/artifacts/containers/dockerfile_checks/inspector-scan-cdx.json"
    inspector_scan = read_test_file(test_file)
    inspector_scan_dict = json.loads(inspector_scan)
    scan_body = inspector_scan_dict["sbom"]
    pkg_vuln.fatal_assert(scan_body is not None, "expected JSON with key 'sbom' but it was not found")
    return scan_body


if __name__ == "__main__":
    unittest.main()
