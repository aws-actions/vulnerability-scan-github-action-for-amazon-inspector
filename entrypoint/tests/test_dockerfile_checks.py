import logging
import os
import unittest

from entrypoint import dockerfile


def read_test_file(file: str) -> str:
    file_contents = ""
    with open(file, "r") as f:
        file_contents = f.read()
    return file_contents


class TestDockerfileChecks(unittest.TestCase):

    def test_is_inspector_cyclonedx_scan(self):
        test_file = "tests/test_data/artifacts/containers/dockerfile_checks/inspector-scan-cdx.json"
        inspector_scan_json = read_test_file(test_file)

        want = True
        got = dockerfile.is_inspector_cyclonedx_scan(inspector_scan_json)
        self.assertEqual(want, got)

    def test_is_cyclonedx_json_v1_5(self):
        test_file = "tests/test_data/artifacts/containers/dockerfile_checks/inspector-scan-cdx.json"
        inspector_scan_json = read_test_file(test_file)
        got = dockerfile.is_cyclonedx_json_v1_5(inspector_scan_json)
        want = True
        self.assertEqual(want, got)

    def test_are_components_present(self):
        test_file = "tests/test_data/artifacts/containers/dockerfile_checks/inspector-scan-cdx.json"
        inspector_scan_json = read_test_file(test_file)
        got = dockerfile.are_components_present(inspector_scan_json)
        want = True
        self.assertEqual(want, got)

    def test_are_vulnerabilities_present(self):
        test_file = "tests/test_data/artifacts/containers/dockerfile_checks/inspector-scan-cdx.json"
        inspector_scan_json = read_test_file(test_file)
        got = dockerfile.are_vulnerabilities_present(inspector_scan_json)
        want = True
        self.assertEqual(want, got)

    def test_get_vuln_array(self):
        test_file = "tests/test_data/artifacts/containers/dockerfile_checks/inspector-scan-cdx.json"
        inspector_scan_json = read_test_file(test_file)

        vulns = dockerfile.get_vuln_array(inspector_scan_json)
        self.assertNotEqual(vulns, "")

        expected_vuln_count = 370
        actual_vuln_count = len(vulns)
        self.assertEqual(expected_vuln_count, actual_vuln_count)

    def test_get_components(self):
        test_file = "tests/test_data/artifacts/containers/dockerfile_checks/inspector-scan-cdx.json"
        inspector_scan_json = read_test_file(test_file)

        components = dockerfile.get_components_array(inspector_scan_json)
        self.assertNotEqual(components, "")

        expected_component_count = 144
        actual_component_count = len(components)
        self.assertEqual(expected_component_count, actual_component_count)

    def test_is_dockerfile_vuln(self):
        vulns = get_vulns()
        dockerfile_vuln_count, other_vuln_count = get_vuln_counts(vulns)

        expected_vuln_count = 6
        self.assertEqual(expected_vuln_count, dockerfile_vuln_count)

        expected_other_count = 364
        self.assertEqual(expected_other_count, other_vuln_count)

    def test_get_inspector_severity(self):
        test_file = "tests/test_data/artifacts/containers/dockerfile_checks/inspector-scan-cdx.json"
        inspector_scan_json = read_test_file(test_file)
        vulns = dockerfile.get_vuln_array(inspector_scan_json)

        for vuln in vulns:
            if dockerfile.is_docker_vuln(vuln):
                severity = dockerfile.get_inspector_severity(vuln)
                self.assertTrue(severity is not None)

    def test_get_affected_components(self):
        test_file = "tests/test_data/artifacts/containers/dockerfile_checks/inspector-scan-cdx.json"
        inspector_scan_json = read_test_file(test_file)
        vulns = dockerfile.get_vuln_array(inspector_scan_json)

        for vuln in vulns:
            affected_components = dockerfile.get_affected_components(vuln)
            self.assertTrue(len(affected_components) > 0)

    def test_get_affected_file(self):
        test_file = "tests/test_data/artifacts/containers/dockerfile_checks/inspector-scan-cdx.json"
        inspector_scan_json = read_test_file(test_file)

        components = dockerfile.get_components_array(inspector_scan_json)
        affected_file = dockerfile.get_affected_file(components, "comp-284")
        self.assertEqual(affected_file, 'dockerfile:comp-1.Dockerfile')

    def test_get_affected_line(self):
        test_file = "tests/test_data/artifacts/containers/dockerfile_checks/inspector-scan-cdx.json"
        inspector_scan_json = read_test_file(test_file)
        components = dockerfile.get_components_array(inspector_scan_json)

        test_comp = "comp-284"
        affected_lines = dockerfile.get_affected_lines(components, test_comp, "IN-DOCKER-005-003")
        self.assertEqual(1, len(affected_lines))
        self.assertEqual(affected_lines[0], "3-3")

    def test_parse_vuln(self):
        test_file = "tests/test_data/artifacts/containers/dockerfile_checks/inspector-scan-cdx.json"
        inspector_scan_json = read_test_file(test_file)

        components = dockerfile.get_components_array(inspector_scan_json)
        vulns = dockerfile.get_vuln_array(inspector_scan_json)

        for vuln in vulns:
            if not dockerfile.is_docker_vuln(vuln):
                continue

            vuln_obj = dockerfile.parse_vuln(vuln, components)
            self.assertTrue("IN-DOCKER-" in vuln_obj.vuln_id)
            self.assertTrue(vuln_obj.severity != "")
            self.assertTrue(vuln_obj.description != "")
            self.assertTrue(len(vuln_obj.filepaths) > 0)
            self.assertTrue(len(vuln_obj.lines) > 0)

    def test_vuln_to_markdown(self):
        markdown_report = dockerfile.get_markdown_header()
        vuln_objects = get_vuln_objects()
        for vuln in vuln_objects:
            row = dockerfile.vuln_to_markdown_row(vuln)
            markdown_report += row

    def test_write_dockerfile_report_csv(self):
        # test that we can parse various reports without throwing exceptions
        test_files = [
            "tests/test_data/artifacts/containers/dockerfile_checks/inspector-scan-cdx.json",
            "tests/test_data/artifacts/containers/dockerfile_checks/inspector-scan-cdx-no-components.json",
            "tests/test_data/artifacts/containers/dockerfile_checks/inspector-scan-cdx-no-vulns.json",
            "tests/test_data/artifacts/containers/dockerfile_checks/inspector-scan-cdx-dockerfile-only.json",
        ]
        dst = "/tmp/test_dockerfile_scan.csv"
        write_counter = 0
        for test_file in test_files:
            if dockerfile.write_dockerfile_report_csv(test_file, dst):
                write_counter += 1
        os.remove(dst)

        expected_writes = 4
        self.assertEqual(expected_writes, write_counter)

    def test_write_dockerfile_report_md(self):
        # test that we can parse various reports without throwing exceptions
        test_files = [
            "tests/test_data/artifacts/containers/dockerfile_checks/inspector-scan-cdx.json",
            "tests/test_data/artifacts/containers/dockerfile_checks/inspector-scan-cdx-no-components.json",
            "tests/test_data/artifacts/containers/dockerfile_checks/inspector-scan-cdx-no-vulns.json",
            "tests/test_data/artifacts/containers/dockerfile_checks/inspector-scan-cdx-dockerfile-only.json",
        ]
        dst = "/tmp/test_dockerfile_scan.md"
        write_counter = 0
        for test_file in test_files:
            if dockerfile.write_dockerfile_report_md(test_file, dst):
                write_counter += 1
        os.remove(dst)

        expected_writes = 4
        self.assertEqual(expected_writes, write_counter)


def get_vuln_objects():
    test_file = "tests/test_data/artifacts/containers/dockerfile_checks/inspector-scan-cdx.json"
    inspector_scan_json = read_test_file(test_file)
    components = dockerfile.get_components_array(inspector_scan_json)
    vulns = dockerfile.get_vuln_array(inspector_scan_json)

    vuln_objects = []
    for vuln in vulns:
        if not dockerfile.is_docker_vuln(vuln):
            continue
        vuln_obj = dockerfile.parse_vuln(vuln, components)
        vuln_objects.append(vuln_obj)

    return vuln_objects


def get_vulns():
    test_file = "tests/test_data/artifacts/containers/dockerfile_checks/inspector-scan-cdx.json"
    inspector_scan_json = read_test_file(test_file)
    vulns = dockerfile.get_vuln_array(inspector_scan_json)
    return vulns


def get_vuln_counts(vulns):
    dockerfile_vuln_count = 0
    other_vuln_count = 0
    for vuln in vulns:
        if dockerfile.is_docker_vuln(vuln):
            dockerfile_vuln_count += 1
        else:
            other_vuln_count += 1
    return dockerfile_vuln_count, other_vuln_count


if __name__ == '__main__':
    unittest.main()
