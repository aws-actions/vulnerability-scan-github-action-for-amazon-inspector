import csv
import logging
import os
from dataclasses import dataclass
from io import StringIO

from entrypoint import pkg_vuln


@dataclass
class InspectorScanResult:
    vulnerabilities: list[pkg_vuln.Vulnerability]
    artifact_name: str = pkg_vuln.NULL_STR
    artifact_type: str = pkg_vuln.NULL_STR
    artifact_hash: str = pkg_vuln.NULL_STR
    build_id: str = pkg_vuln.NULL_STR
    criticals: str = pkg_vuln.NULL_STR
    highs: str = pkg_vuln.NULL_STR
    mediums: str = pkg_vuln.NULL_STR
    lows: str = pkg_vuln.NULL_STR
    others: str = pkg_vuln.NULL_STR

    def total_vulns(self) -> int:
        total_vulns = int(self.criticals) + int(self.highs) + int(self.mediums) + int(self.lows) + int(self.others)
        return total_vulns


def to_csv(scan_result: InspectorScanResult):
    csv_buffer = StringIO()
    csv_writer = csv.writer(csv_buffer, quoting=csv.QUOTE_ALL)

    # insert hash rows; these are like properties for CSV
    artifact_info = [
        f"#artifact_name:{scan_result.artifact_name}",
        f"artifact_type:{scan_result.artifact_type}",
        f"artifact_hash:{scan_result.artifact_hash}",
        f"build_id:{scan_result.build_id}",
    ]
    csv_writer.writerow(artifact_info)

    vuln_summary = [
        f"#critical_vulnerabilities:{scan_result.criticals}",
        f"high_vulnerabilities:{scan_result.highs}",
        f"medium_vulnerabilities:{scan_result.mediums}",
        f"low_vulnerabilities:{scan_result.lows}",
        f"other_vulnerabilities:{scan_result.others}",
    ]
    csv_writer.writerow(vuln_summary)

    # write the header into the CSV
    header = [
        "ID",
        "Severity",
        "Source",
        "CVSS",
        "Installed Package",
        "Fixed Package",
        "Path",
        "EPSS",
        "Exploit Available",
        "Exploit Last Seen",
        "CWEs",
    ]
    csv_writer.writerow(header)

    # write each vuln into a CSV
    if scan_result.vulnerabilities:
        for v in scan_result.vulnerabilities:
            # if package vuln
            row = [
                v.vuln_id,
                v.severity,
                v.severity_provider,
                v.cvss_score,
                v.installed_ver,
                v.fixed_ver,
                v.pkg_path,
                v.epss_score,
                v.exploit_available,
                v.exploit_last_seen,
                v.cwes,
            ]
            csv_writer.writerow(row)

    csv_str = csv_buffer.getvalue()
    csv_buffer.close()

    return csv_str


def to_markdown(scan_result: InspectorScanResult):
    markdown = create_header_info(scan_result)
    markdown += create_summary_table(scan_result)

    if not scan_result.vulnerabilities:
        markdown += (
            ":green_circle: Your artifact was scanned with Amazon Inspector and no vulnerabilities were detected."
        )
    else:
        markdown += create_vulnerability_details_table(scan_result.vulnerabilities)

    markdown += "\n\n"
    return markdown


def create_header_info(scan_result: InspectorScanResult):
    markdown = "# Amazon Inspector Scan Results\n"

    if not scan_result.artifact_name == "./":
        markdown += f"Artifact Name: {scan_result.artifact_name}\n\n"

    artifact_type = "repository" if scan_result.artifact_type == "directory" else scan_result.artifact_type
    markdown += f"Artifact Type: {artifact_type}\n\n"

    if scan_result.artifact_hash != pkg_vuln.NULL_STR:
        markdown += f"Artifact Hash: {scan_result.artifact_hash}\n\n"
    if scan_result.build_id != pkg_vuln.NULL_STR:
        markdown += f"Build ID: {scan_result.build_id}\n\n"
    return markdown


def create_summary_table(scan_result: InspectorScanResult):
    markdown = "## Vulnerability Counts by Severity\n\n"
    markdown += "| Severity | Count |\n"
    markdown += "|----------|-------|\n"
    markdown += f"| Critical | {scan_result.criticals}|\n"
    markdown += f"| High     | {scan_result.highs}|\n"
    markdown += f"| Medium   | {scan_result.mediums}|\n"
    markdown += f"| Low      | {scan_result.lows}|\n"
    markdown += f"| Other    | {scan_result.others}|\n"
    markdown += "\n\n"
    return markdown


def create_vulnerability_details_table(vulns: list[pkg_vuln.Vulnerability]):
    markdown = "## Vulnerability Findings\n\n"

    rows = []
    details_table_header_columns = [
        "ID",
        "Severity",
        "Source",
        "[CVSS](https://www.first.org/cvss/)",
        "Installed Package ([PURL](https://github.com/package-url/purl-spec/tree/master?tab=readme-ov-file#purl))",
        "Fixed Package",
        "Path",
        "[EPSS](https://www.first.org/epss/)",
        "Exploit Available",
        "Exploit Last Seen",
        "CWEs",
    ]
    details_table_header = [
        generate_markdown_row(*details_table_header_columns),
        generate_markdown_row(*["-" * 7 for i in range(len(details_table_header_columns))]),
    ]
    rows.extend(details_table_header)

    vulns = sort_vulns_by_cvss_score(vulns)
    for v in vulns:
        rows.append(
            generate_markdown_row(
                v.vuln_id,
                clean_null(v.severity),
                clean_null(v.severity_provider),
                clean_null(v.cvss_score),
                merge_cell(v.installed_ver),
                merge_cell(v.fixed_ver),
                merge_cell(clean_null(v.pkg_path)),
                clean_null(v.epss_score),
                clean_null(v.exploit_available),
                clean_null(v.exploit_last_seen),
                merge_cell(clean_null(v.cwes)),
            )
        )
    markdown += "\n".join(rows)
    return markdown


def generate_markdown_row(*cells):
    row_text = "| " + " | ".join(cells) + " |"
    return row_text


def clean_null(a_string: str):
    if a_string == pkg_vuln.NULL_STR:
        return ""
    else:
        return a_string


def merge_cell(a_string: str):
    """
    This function expects a string of data
    that is intended to be placed in a markdown
    table. The provided data may include multiple
    elements in a string, such as multiple PURLs
    separated with a semi-colon character ';'.
    This function splits the provided string
    so that multiple elements can fit in one
    cell in a markdown table.
    """

    # return early on empty string
    if a_string == "":
        return ""

    # we may have multiple PURLs for a single CVE,
    # so split purls into a list we can iterate on
    original_list = a_string.split(";")
    seen = set()
    unique_list = []

    # make each PURL list unique while preserving ordering
    # so that our pkg versions line up with the correct pkg names
    for item in original_list:
        if item not in seen:
            seen.add(item)
            unique_list.append(item)

    unique_formatted = []
    for each in unique_list:
        # make each element preformatted text,
        # otherwise the markdown report renders
        # with malformed characters on GitHub
        each = f"`{each}`"
        unique_formatted.append(each)

    # separate multiple elements in cell with HTML break characters
    merged_cell = "<br><br>".join(unique_formatted)
    return merged_cell


def sort_vulns_by_cvss_score(vulns):
    for each in vulns:
        if each.cvss_score == pkg_vuln.NULL_STR:
            each.cvss_score = 0

    sorted_vulns = sorted(vulns, key=lambda obj: float(obj.cvss_score), reverse=True)

    for each in sorted_vulns:
        if each.cvss_score == 0:
            each.cvss_score = pkg_vuln.NULL_STR
    return sorted_vulns


def post_github_step_summary(markdown):
    step_summary_path = "/tmp/inspector.md"
    if os.getenv("GITHUB_ACTIONS"):
        step_summary_path = os.environ["GITHUB_STEP_SUMMARY"]

    try:
        with open(step_summary_path, "a") as f:
            f.write(markdown)
    except Exception as e:
        logging.error(e)
        return
