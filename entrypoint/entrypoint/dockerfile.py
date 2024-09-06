import json
import logging

from typing import List


class DockerfileVulnerability:
    def __int__(self):
        self.vuln_id: str = ""
        self.severity: str = ""
        self.description: str = ""

        # for a single Dockerfile vulnerability, we
        # may have multiple affected files and line numbers
        self.filepaths = []
        self.lines = []


def get_json_value(key: str, inspector_scan_json: dict):
    value = inspector_scan_json.get(key)
    return value


def get_json_value_or_throw_fatal_error(key: str, inspector_scan_json: dict):
    value = get_json_value(key, inspector_scan_json)
    if not value:
        logging.fatal(f"expected JSON with key '{key}' but it was not found")

    return value


def get_inspector_scan_body(inspector_scan_json):
    scan_json = json.loads(inspector_scan_json)
    scan_body = get_json_value("sbom", scan_json)
    if not scan_body:
        logging.fatal("expected JSON with key 'sbom' but none was found")
    return scan_body


def is_inspector_cyclonedx_scan(inspector_scan: str) -> bool:
    scan_body = get_inspector_scan_body(inspector_scan)

    scan_format = get_json_value_or_throw_fatal_error("bomFormat", scan_body)

    if scan_format == "CycloneDX":
        return True

    return False


def is_cyclonedx_json_v1_5(inspector_scan_json: str) -> bool:
    scan_body = get_inspector_scan_body(inspector_scan_json)
    spec_version = get_json_value_or_throw_fatal_error("specVersion", scan_body)
    if spec_version == "1.5":
        return True

    return False


def are_components_present(inspector_scan_json: str) -> bool:
    scan_body = get_inspector_scan_body(inspector_scan_json)
    components = get_json_value("components", scan_body)
    if not components:
        return False

    return True


def are_vulnerabilities_present(inspector_scan_json: str) -> bool:
    scan_body = get_inspector_scan_body(inspector_scan_json)
    vulnerabilities = get_json_value("vulnerabilities", scan_body)
    if not vulnerabilities:
        return False

    return True


def get_vuln_array(inspector_scan_json: str):
    scan_body = get_inspector_scan_body(inspector_scan_json)
    vulnerabilities = get_json_value("vulnerabilities", scan_body)
    if not vulnerabilities:
        return None

    return vulnerabilities


def get_components_array(inspector_scan_json: str):
    scan_body = get_inspector_scan_body(inspector_scan_json)
    components = get_json_value("components", scan_body)
    if not components:
        return None

    return components


def is_docker_vuln(vuln):
    vuln_id = vuln["id"]

    if "IN-DOCKER-" in vuln_id:
        return True

    return False


def parse_vuln(dockerfile_vulnerability, component_list) -> DockerfileVulnerability:
    affected_components = get_affected_components(dockerfile_vulnerability)
    affected_files = []
    affected_lines = []

    v = DockerfileVulnerability()
    v.vuln_id = dockerfile_vulnerability["id"]

    for each_component in affected_components:
        filepath = get_affected_file(component_list, each_component)
        affected_files.append(filepath)

        lines = get_affected_lines(component_list, each_component, v.vuln_id)
        for each_line in lines:
            affected_lines.append(each_line)

    v.severity = get_inspector_severity(dockerfile_vulnerability)
    v.description = dockerfile_vulnerability["description"]
    v.filepaths = affected_files
    v.lines = affected_lines

    return v


def get_inspector_severity(vuln):
    ratings = get_ratings(vuln)
    if not ratings:
        return None

    for rating in ratings:
        source = get_source(rating)
        if not source:
            continue

        source_name = get_source_name(source)
        if not source_name:
            continue

        if "AMAZON_INSPECTOR" in source_name:
            severity = get_severity(rating)
            return severity

    return None


def get_ratings(vuln):
    ratings = vuln["ratings"]
    if not ratings:
        logging.error(f"expected severity ratings in vuln but none was found: {vuln}")
        return None
    return ratings


def get_source(rating):
    source = rating["source"]
    if not source:
        logging.error(f"expected rating source but none was found: {rating}")
        return None

    return source


def get_source_name(source):
    name = source["name"]
    if not name:
        logging.error(f"expected source name but none was found: {source}")
        return None

    return name


def get_severity(rating):
    severity = rating["severity"]
    if not severity:
        logging.error(f"expected severity in rating object but it was not found: {rating}")
        return None

    return severity


def get_affected_file(components, comp_number):
    for each_comp in components:
        bom_ref = each_comp["bom-ref"]
        if bom_ref == comp_number:
            affected_dockerfile = each_comp["name"]
            return affected_dockerfile


def get_affected_components(vuln):
    affects = vuln['affects']
    if not affects:
        logging.error(f"expected 'affects' list in vulnerability but it was not found: {vuln}")
        return None

    affected_components = []
    for each_comp in affects:
        comp_name = each_comp["ref"]
        if not comp_name:
            logging.error(f"expected value from key 'ref' but received None: {each_comp}")
            continue
        affected_components.append(comp_name)

    return affected_components


def get_affected_lines(component_list, bom_ref, docker_finding_id):
    affected_prop = f"amazon:inspector:sbom_scanner:dockerfile_finding:{docker_finding_id}"
    affected_lines_list = []

    # get the affected lines from the component matching 'bom_ref'
    # and 'docker_finding_id'
    comp = get_matching_component(component_list, bom_ref)
    properties = comp["properties"]
    for prop in properties:
        prop_name = prop["name"]
        if prop_name != affected_prop:
            continue
        affected_lines = prop["value"]
        affected_lines = extract_line_numbers(affected_lines)
        affected_lines_list.append(affected_lines)

    return affected_lines_list


def get_matching_component(component_list, bom_ref):
    for each_comp in component_list:
        comp_name = each_comp["bom-ref"]
        if comp_name == bom_ref:
            return each_comp


def extract_line_numbers(affected_lines):
    affected_lines = affected_lines.split(":")
    affected_lines = affected_lines[1]
    return affected_lines


def get_component(inspector_scan_cdx_json, comp_number):
    components = get_components_array(inspector_scan_cdx_json)
    for each_comp in components:
        bom_ref = each_comp["bom-ref"]
        if comp_number == bom_ref:
            return each_comp


def vuln_to_markdown_row(vuln: DockerfileVulnerability) -> str:
    if len(vuln.filepaths) == 1:
        vuln.filepaths = vuln.filepaths[0]

    if len(vuln.lines) == 1:
        vuln.lines = vuln.lines[0]
    row = f"| {vuln.vuln_id} | {vuln.severity} | {vuln.description} | {vuln.filepaths} | {vuln.lines} |\n"
    return row


def get_markdown_header() -> str:
    s = "## Dockerfile Findings\n"
    s += "|ID|SEVERITY|DESCRIPTION|FILE|LINES|\n"
    s += "|---|---|---|---|---|\n"
    return s

def get_markdown_header_no_vulns() -> str:
    s = "## Dockerfile Findings\n"
    return s

def get_dockerfile_vulns(inspector_scan_path):
    vuln_objects = []
    inspector_scan_json = []
    with open(inspector_scan_path, "r") as f:
        inspector_scan_json = f.read()

    components = get_components_array(inspector_scan_json)
    if not components: return vuln_objects

    vulns = get_vuln_array(inspector_scan_json)
    if not vulns: return vuln_objects

    for vuln in vulns:
        if not is_docker_vuln(vuln):
            continue
        vuln_obj = parse_vuln(vuln, components)
        vuln_objects.append(vuln_obj)

    return vuln_objects


def get_csv_report_header():
    header = "ID,SEVERITY,DESCRIPTION,FILE,LINE\n"
    return header


def vuln_to_csv_row(vuln):
    if len(vuln.filepaths) == 1:
        vuln.filepaths = vuln.filepaths[0]

    if len(vuln.lines) == 1:
        vuln.lines = vuln.lines[0]

    clean_description = f"{vuln.description.replace(',', '')}"
    row = f"{vuln.vuln_id},{vuln.severity},{clean_description},{vuln.filepaths},{vuln.lines}\n"
    return row


def dockerfile_vulns_to_csv(dockerfile_vulns):
    csv_output = get_csv_report_header()

    for vuln in dockerfile_vulns:
        csv_row = vuln_to_csv_row(vuln)
        csv_output += csv_row

    return csv_output


def write_dockerfile_report_csv(inspector_scan_path, dst_file):
    dockerfile_vulns = get_dockerfile_vulns(inspector_scan_path)

    csv_output = dockerfile_vulns_to_csv(dockerfile_vulns)

    logging.info(f"writing Dockerfile vulnerability CSV report to: {dst_file}")
    with open(dst_file, "w") as f:
        f.write(csv_output)
        return True


def write_dockerfile_report_md(inspector_scan_path, dst_file):
    dockerfile_vulns = get_dockerfile_vulns(inspector_scan_path)

    markdown_report = ""
    if len(dockerfile_vulns) == 0:
        markdown_report = get_markdown_header_no_vulns()
        row = "\n\n:green_circle: Amazon Inspector scanned for security issues in Dockerfiles and no issues were found."
        markdown_report += row
    else:
        markdown_report = get_markdown_header()
        for vuln in dockerfile_vulns:
            row = vuln_to_markdown_row(vuln)
            markdown_report += row

    logging.info(f"writing Dockerfile vulnerability markdown report to: {dst_file}")
    with open(dst_file, "w") as f:
        f.write(markdown_report)
        return True


def post_dockerfile_github_actions_step_summary():
    return
