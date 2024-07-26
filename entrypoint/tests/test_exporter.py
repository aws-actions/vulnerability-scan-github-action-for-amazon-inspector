import json
import os
import unittest

from entrypoint import exporter, pkg_vuln


class TestExporter(unittest.TestCase):
    TEST_DIR = "tests/test_data/scans/"
    TEST_RESULT_DIR = "tests/test_data/scan_results/"
    CSV_EXTENSION = ".csv"
    MARKDOWN_EXTENSION = ".md"

    def test_json_to_csv(self):
        file_list = os.listdir(self.TEST_DIR)
        for file in file_list:
            with self.subTest(msg=file):

                test_file_path = os.path.join(self.TEST_DIR, file)
                inspector_scan_json = {}
                with open(test_file_path, "r") as f:
                    inspector_scan_json = json.load(f)

                vulns = pkg_vuln.parse_inspector_scan_result(inspector_scan_json)

                scan_result = exporter.InspectorScanResult(vulnerabilities=vulns)
                as_csv = exporter.to_csv(scan_result)

                expected_data_path = os.path.join(self.TEST_RESULT_DIR, file) + self.CSV_EXTENSION
                with open(expected_data_path, "r", newline="\n") as f:
                    expected_csv = f.read()
                self.assertEqual(expected_csv, as_csv, file)

    def test_json_to_markdown(self):
        file_list = os.listdir(self.TEST_DIR)
        for file in file_list:
            with self.subTest(msg=file):

                path = os.path.join(self.TEST_DIR, file)
                inspector_scan_json = {}
                with open(path, "r") as f:
                    inspector_scan_json = json.load(f)

                vulns = pkg_vuln.parse_inspector_scan_result(inspector_scan_json)

                scan_result = exporter.InspectorScanResult(vulnerabilities=vulns)
                as_markdown = exporter.to_markdown(scan_result)
                exporter.post_github_step_summary(as_markdown)

                expected_data_path = os.path.join(self.TEST_RESULT_DIR, file) + self.MARKDOWN_EXTENSION
                with open(expected_data_path, "r", newline="\n") as f:
                    expected_markdown = f.read()
                self.assertEqual(expected_markdown, as_markdown, file)


if __name__ == "__main__":
    unittest.main()
