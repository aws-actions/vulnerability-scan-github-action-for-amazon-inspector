"""
pkg_vuln.py has functions for parsing
Inspector ScanSbom API JSON, and converting
to different formats (CSV and markdown).
"""

import logging
import urllib.parse
from dataclasses import dataclass
from typing import List

NULL_STR = "null"


class CvssSourceProvider:
    NVD = "NVD"
    MITRE = "MITRE"
    GITHUB = "GITHUB"
    GITLAB = "GITLAB"
    REDHAT_CVE = "REDHAT_CVE"
    UBUNTU_CVE = "UBUNTU_CVE"
    AMAZON_INSPECTOR = "AMAZON_INSPECTOR"
    DEFAULT_PROVIDER = NVD

def get_rating_providers():
    """
    get_rating_providers returns a list of vulnerability
    severity providers. The action uses this information
    to determine which vuln severity to render when
    multiple severity values are present from different
    vendors. See the function definition to view the
    order in which severity providers are preferred.
    """

    # NVD is most preferred, followed by everything
    # else in the order listed.
    providers = [CvssSourceProvider.NVD,
                 CvssSourceProvider.MITRE,
                 CvssSourceProvider.GITHUB,
                 CvssSourceProvider.GITLAB,
                 CvssSourceProvider.AMAZON_INSPECTOR
                 ]
    return providers

class CvssSeverity:
    UNTRIAGED = "untriaged"
    UNKNOWN = "unknown"


@dataclass
class Vulnerability:
    """
    Vulnerability is an object for marshalling
    vulnerability findings from Inspector's
    ScanSbom JSON into a python object that can
    be queried and manipulated
    """

    vuln_id: str = NULL_STR
    severity: str = NULL_STR
    severity_provider: str = NULL_STR
    cvss_score: str = NULL_STR
    published: str = NULL_STR
    modified: str = NULL_STR
    description: str = NULL_STR
    installed_ver: str = NULL_STR
    fixed_ver: str = NULL_STR
    pkg_path: str = NULL_STR
    epss_score: str = NULL_STR
    exploit_available: str = NULL_STR
    exploit_last_seen: str = NULL_STR
    cwes: str = NULL_STR


@dataclass
class CvssRating:
    severity: str = CvssSeverity.UNTRIAGED
    provider: str = CvssSourceProvider.DEFAULT_PROVIDER
    cvss_score: str = NULL_STR


@dataclass
class AffectedPackages:
    purl_list_str: str = NULL_STR
    path_list_str: str = NULL_STR


def parse_inspector_scan_result(inspector_scan_json) -> List[Vulnerability]:
    """
    this function parses JSON from Inspector's ScanSbom API
    and returns a list of vulnerability objects.
    """

    vuln_list: List[Vulnerability] = []

    # check if the input has the fields we expect; anything without
    # these fields is assumed to be garbage and None is returned
    scan_contents = inspector_scan_json.get("sbom")
    fatal_assert(scan_contents is not None, "expected JSON with key 'sbom' but none was found")

    components = scan_contents.get("components")
    if not components:
        return vuln_list

    vulns = scan_contents.get("vulnerabilities")
    if not vulns:
        return vuln_list

    pkg_vulns = get_pkg_vulns(vulns)

    for v in pkg_vulns:
        vuln_obj = convert_package_vuln_to_vuln_obj(v, components)
        vuln_list.append(vuln_obj)

    return vuln_list


def fatal_assert(expr: bool, msg: str):
    if not expr:
        logging.error(msg)
        exit(1)


def get_pkg_vulns(inspector_scan_vulns: dict):
    pkg_vulns = []

    for vuln in inspector_scan_vulns:
        # [!] at time of writing, we only have two vuln types:
        # 1. pkg vulns, 2. Dockerfile vulns
        # Therefore, we skip all Dockerfile vulns, leaving
        # only pkg vulns.
        if "IN-DOCKER" in vuln["id"]:
            continue
        pkg_vulns.append(vuln)

    return pkg_vulns


def convert_package_vuln_to_vuln_obj(v, components) -> Vulnerability:
    vuln_obj = Vulnerability()

    vuln_obj.vuln_id = v.get("id", NULL_STR)
    vuln_obj.published = v.get("created", NULL_STR)
    vuln_obj.modified = v.get("updated", NULL_STR)

    ratings = v.get("ratings")
    add_ratings(ratings, vuln_obj)

    description = v.get("description")
    add_description(description, vuln_obj)

    affected_packages = get_affected_packages(v, components)
    vuln_obj.installed_ver = affected_packages.purl_list_str
    vuln_obj.pkg_path = affected_packages.path_list_str

    fixed_str = get_fixed_package(v)
    vuln_obj.fixed_ver = fixed_str

    exploit_available = getPropertyValueFromKey(v, "amazon:inspector:sbom_scanner:exploit_available")
    vuln_obj.exploit_available = exploit_available if exploit_available else NULL_STR

    exploit_last_seen = getPropertyValueFromKey(v, "amazon:inspector:sbom_scanner:exploit_last_seen_in_public")
    vuln_obj.exploit_last_seen = exploit_last_seen if exploit_last_seen else NULL_STR

    cwe_list_str = get_cwes(v)
    vuln_obj.cwes = cwe_list_str
    return vuln_obj


def add_ratings(ratings, vulnerability):
    if ratings is None:
        return

    rating = get_cvss_rating(ratings, vulnerability)
    vulnerability.severity = rating.severity
    vulnerability.severity_provider = rating.provider
    vulnerability.cvss_score = rating.cvss_score

    epss_score = get_epss_score(ratings)
    if epss_score:
        vulnerability.epss_score = epss_score


def add_description(description, vulnerability):
    if description is None:
        return NULL_STR

    vuln_desc = description.strip()
    vuln_desc = vuln_desc.replace("\n", " ")
    vuln_desc = vuln_desc.replace("\t", " ")
    vulnerability.description = vuln_desc


def get_affected_packages(v, components) -> AffectedPackages:
    affected_package_urls = []
    affected_package_paths = []

    affected_bom_refs = v.get("affects")
    if not affected_bom_refs:
        return AffectedPackages()

    flattened_components = flatten_nested_components(components)
    for component in flattened_components:
        for bom_ref in affected_bom_refs:
            ref = component.get("bom-ref")
            if not ref:
                continue
            if ref == bom_ref["ref"]:
                purl = component.get("purl")
                if purl:
                    purl = urllib.parse.unquote(purl)
                    affected_package_urls.append(purl)
                pkg_path = getPropertyValueFromKey(component, "amazon:inspector:sbom_scanner:path")
                if pkg_path:
                    affected_package_paths.append(pkg_path)

    purl_str = combine_str_list_into_one_str(affected_package_urls)
    path_str = combine_str_list_into_one_str(affected_package_paths)
    return AffectedPackages(purl_list_str=purl_str, path_list_str=path_str)


def get_fixed_package(v):
    # get fixed package
    fixed_versions: List[str] = []
    props = v.get("properties")
    if not props:
        fixed_versions_str = combine_str_list_into_one_str(fixed_versions)
        return fixed_versions_str

    for each_prop in props:
        prop_name = each_prop.get("name")
        if prop_name:
            if "amazon:inspector:sbom_scanner:fixed_version:comp-" in prop_name:
                fixed_version = each_prop.get("value")
                if fixed_version:
                    fixed_versions.append(fixed_version)

    fixed_versions_str = combine_str_list_into_one_str(fixed_versions)
    return fixed_versions_str


def getPropertyValueFromKey(vuln_json, key):
    """
    extracts cycloneDX properties from Inspector
    ScanSbom components
    :param vuln_json: the component from which you would like to extract a property value
    :param key: the key to the property
    :return: the value from the component's property key
    """
    props = vuln_json.get("properties")
    if not props:
        return None

    for each_prop in props:
        name = each_prop.get("name")
        if name:
            if key == name:
                value = each_prop.get("value")
                if value:
                    return value
    return None


def get_cwes(v) -> str:
    cwes = v.get("cwes")

    cwe_list = []
    if not cwes:
        return NULL_STR

    for each_cwe in cwes:
        s = f"CWE-{each_cwe}"
        cwe_list.append(s)

    cwe_str = combine_str_list_into_one_str(cwe_list)
    return cwe_str


def get_cvss_rating(ratings, vulnerability) -> CvssRating:
    rating_provider_priority = get_rating_providers()
    for provider in rating_provider_priority:
        for rating in ratings:
            if rating["source"]["name"] != provider:
                continue

            severity = CvssSeverity.UNTRIAGED if rating["severity"] == CvssSeverity.UNKNOWN else rating["severity"]
            cvss_score = str(rating["score"]) if rating["method"] == "CVSSv31" else "null"
            if severity and cvss_score:
                return CvssRating(severity=severity, provider=provider, cvss_score=cvss_score)

    logging.info(f"No CVSS rating is provided for {vulnerability.vuln_id}")
    return CvssRating()


def get_epss_score(ratings):
    for rating in ratings:
        source = rating.get("source")
        if not source:
            continue

        if source["name"] == "EPSS":
            epss_score = rating["score"]
            if epss_score:
                return str(epss_score)
    return None


def flatten_nested_components(components):
    flattened_components = []
    for each_component in components:
        flattened_components.append(each_component)
        if "components" in each_component:
            nested_components = flatten_nested_components(each_component["components"])
            flattened_components.extend(nested_components)
    return flattened_components


def combine_str_list_into_one_str(str_list: list[str]) -> str:
    str_element = ";".join(str_list)
    if str_element == "":
        str_element = NULL_STR
    return str_element
