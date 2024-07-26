import os
import unittest
from collections import namedtuple

from entrypoint import dockerfile, exporter, orchestrator


class TestOrchestrator(unittest.TestCase):

    def test_get_vuln_counts(self):
        # verify we can successfully parse all known-valid Inspector scans
        test_dir = "tests/test_data/scans/"
        file_list = os.listdir(test_dir)
        for file in file_list:
            path = os.path.join(test_dir, file)
            succeeded = orchestrator.get_vuln_counts(path)
            self.assertTrue(succeeded)

        # verify our vuln counts are correct
        succeeded, criticals, highs, mediums, lows, others = orchestrator.get_vuln_counts(
            "tests/test_data/scans/alpine:3.18.2.json.scan"
        )
        self.assertTrue(succeeded)
        self.assertEqual(criticals, 1)
        self.assertEqual(highs, 1)
        self.assertEqual(mediums, 7)
        self.assertEqual(lows, 0)
        self.assertEqual(others, 3)

    def test_get_summarized_findings(self):
        criticals = highs = mediums = lows = others = 10
        scan_result = exporter.InspectorScanResult(
            vulnerabilities=[],
            criticals=criticals,
            highs=highs,
            mediums=mediums,
            lows=lows,
            others=others,
            artifact_name="test_artifact",
            artifact_type="repository",
        )

        findings = orchestrator.get_summarized_findings(scan_result).splitlines()
        expected = """
    ------------------------------------
    Amazon Inspector Scan Summary:
    Artifact Name: test_artifact
    Artifact Type: repository
    YYYY-MM-DD hh:mm:ss
    ------------------------------------
    Total Vulnerabilities: 50
    Critical:   10
    High:       10
    Medium:     10
    Low:        10
    Other:      10
    """

        lineForTimeStamp = 5
        for i, line in enumerate(expected.splitlines()):
            if lineForTimeStamp != i:
                self.assertEqual(line, findings[i])

    def test_thresholds(self):
        criticals = highs = mediums = lows = others = 10
        threshold_exceeded = orchestrator.exceeds_threshold(criticals, 1, highs, 1, mediums, 1, lows, 1, others, 1)
        self.assertTrue(threshold_exceeded)

        criticals = highs = mediums = lows = others = 0
        threshold_exceeded = orchestrator.exceeds_threshold(criticals, 0, highs, 0, mediums, 0, lows, 0, others, 0)
        self.assertFalse(threshold_exceeded)

    def test_inspector_scan(self):
        src = "tests/test_data/sboms/alpine:3.18.2.json"
        dst = "/tmp/inspector_scan_alpine.3.18.2.json"
        ret = orchestrator.invoke_inspector_scan(src, dst)
        self.assertEqual(ret, 0)

    def test_write_pkg_vuln_report_csv(self):
        out_scan_csv = "/tmp/out_scan.csv"
        scan_result = exporter.InspectorScanResult(
            vulnerabilities=[],
            criticals=1,
            highs=2,
            mediums=3,
            lows=4,
            others=5,
            artifact_name="test_artifact",
            artifact_type="repository",
        )
        orchestrator.write_pkg_vuln_report_csv(out_scan_csv, scan_result)
        return

    def test_write_markdown_to_disk(self):
        out_scan_markdown = "/tmp/out_scan.md"
        scan_result = exporter.InspectorScanResult(
            vulnerabilities=[],
            criticals=1,
            highs=1,
            mediums=1,
            lows=1,
            others=1,
            artifact_name="test_artifact",
            artifact_type="repository",
        )
        orchestrator.write_pkg_vuln_report_markdown(out_scan_markdown, scan_result)
        return

    def test_system_against_dockerfile_findings(self):
        test_files = [
            "tests/test_data/artifacts/containers/dockerfile_checks/inspector-scan-cdx.json",
            "tests/test_data/artifacts/containers/dockerfile_checks/inspector-scan-cdx-no-components.json",
            "tests/test_data/artifacts/containers/dockerfile_checks/inspector-scan-cdx-no-vulns.json",
            "tests/test_data/artifacts/containers/dockerfile_checks/inspector-scan-cdx-dockerfile-only.json",
        ]

        for test_file in test_files:
            ArgMock = namedtuple(
                "args",
                [
                    "out_scan",
                    "artifact_path",
                    "artifact_type",
                    "out_scan_csv",
                    "out_scan_markdown",
                    "out_dockerfile_scan_csv",
                    "out_dockerfile_scan_md",
                ],
            )
            args = ArgMock(
                out_scan=test_file,
                artifact_path=test_file,
                artifact_type="container",
                out_scan_csv="/tmp/out_scan.csv",
                out_scan_markdown="/tmp/out_scan.md",
                out_dockerfile_scan_csv="/tmp/out_dockerfile_scan.csv",
                out_dockerfile_scan_md="/tmp/out_dockerfile_scan.md",
            )

            succeeded, scan_result = orchestrator.get_scan_result(args)
            self.assertTrue(succeeded)

            orchestrator.write_pkg_vuln_report_csv(args.out_scan_csv, scan_result)
            orchestrator.write_pkg_vuln_report_markdown(args.out_scan_markdown, scan_result)
            dockerfile.write_dockerfile_report_csv(args.out_scan, args.out_dockerfile_scan_csv)
            dockerfile.write_dockerfile_report_md(args.out_scan, args.out_dockerfile_scan_md)

    def test_get_sbomgen_arch(self):

        test_cases = [
            # supported platforms (ARM and Intel 64-bit)
            {"input": "x86_64", "expected": "amd64"},
            {"input": "amd64", "expected": "amd64"},
            {"input": "arm64", "expected": "arm64"},
            {"input": "aarch64", "expected": "arm64"},
            # test case insensitivity
            {"input": "X86_64", "expected": "amd64"},
            {"input": "AMD64", "expected": "amd64"},
            {"input": "ARM64", "expected": "arm64"},
            {"input": "aARCh64", "expected": "arm64"},
            # unsupported platforms (32-bit, non-intel, non-arm)
            {"input": "arm", "expected": None},
            {"input": "armv6l", "expected": None},
            {"input": "armv7l", "expected": None},
            {"input": "armv8l", "expected": None},
            {"input": "i386", "expected": None},
            {"input": "i486", "expected": None},
            {"input": "i586", "expected": None},
            {"input": "i686", "expected": None},
            {"input": "ppc", "expected": None},
            {"input": "ppc64", "expected": None},
            {"input": "ppc64le", "expected": None},
            {"input": "sparc", "expected": None},
            {"input": "sparc64", "expected": None},
            {"input": "mips", "expected": None},
            {"input": "mips64", "expected": None},
            # malformed input
            {"input": "garbage", "expected": None},
            {"input": "213123123123", "expected": None},
            {"input": "", "expected": None},
            {"input": None, "expected": None},
        ]

        for each_test in test_cases:
            result = orchestrator.get_sbomgen_arch(each_test["input"])
            self.assertEqual(result, each_test["expected"])


if __name__ == "__main__":
    unittest.main()
