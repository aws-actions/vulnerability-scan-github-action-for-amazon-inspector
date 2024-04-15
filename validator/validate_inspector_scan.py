#!/usr/bin/env python3

"""
This script validates the contents of an Inspector ScanSbom
response to ensure that fields needed by the
Inspector GitHub Actions plugin are present.
"""

import argparse
import json
import logging
import sys


def assert_equal(key, want, got):
    if want != got:
        logging.error(f" expected JSON value of '{want}' from key '{key}', but received '{got}'")
        sys.exit(1)


def is_valid_prop_name(prop_name):
    if 'amazon:inspector:sbom_scanner:critical_vulnerabilities' in prop_name:
        return True
    elif 'amazon:inspector:sbom_scanner:high_vulnerabilities' in prop_name:
        return True
    elif 'amazon:inspector:sbom_scanner:medium_vulnerabilities' in prop_name:
        return True
    elif 'amazon:inspector:sbom_scanner:low_vulnerabilities' in prop_name:
        return True
    elif 'amazon:inspector:sbom_scanner:other_vulnerabilities' in prop_name:
        return True
    else:
        logging.error(f"received unhandled property name: '{prop_name}'")
        sys.exit(1)


def validate_inspector_scan(scan_sbom_json):
    scan_sbom_json = scan_sbom_json.get("sbom")
    assert scan_sbom_json != ""

    want = "CycloneDX"
    key = "bomFormat"
    got = scan_sbom_json.get(key)
    assert_equal(key, want, got)

    want = "1.5"
    key = "specVersion"
    got = scan_sbom_json.get(key)
    assert_equal(key, want, got)

    key = "serialNumber"
    got = scan_sbom_json.get(key)
    assert got != ""

    components = scan_sbom_json.get("components")
    assert len(components) > 0

    vulns = scan_sbom_json.get("vulnerabilities")
    assert len(vulns) > 0

    props = scan_sbom_json.get("metadata").get("properties")
    for each_prop in props:
        prop_name = each_prop.get("name")
        assert is_valid_prop_name(prop_name)


def open_inspector_scan(filepath):
    scan_json = ""
    f = None
    try:
        f = open(filepath, "r")
    except Exception as e:
        logging.error(f"unable to open file for reading: {filepath}\n{e}")
        sys.exit(1)

    try:
        scan_json = json.load(f)
    except Exception as e:
        logging.error(f"unable to load file as JSON: {filepath}\n{e}")
        sys.exit(1)

    return scan_json


def main():
    parser = argparse.ArgumentParser(description="Validate the contents of an Inspector ScanSbom JSON payload")
    parser.add_argument("--file", type=str, default="", required=True,
                        help="The filepath to an Inspector ScanSbom JSON file")
    args = parser.parse_args()

    inspector_scan_json = open_inspector_scan(args.file)
    validate_inspector_scan(inspector_scan_json)
    logging.info("validation successful")


if __name__ == "__main__":
    logging.basicConfig(level=logging.DEBUG)
    main()
