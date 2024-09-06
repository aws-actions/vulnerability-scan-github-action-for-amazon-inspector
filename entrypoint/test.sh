#!/bin/bash

python3 main.py \
    --artifact-type="container" \ 
    --artifact-path="alpine:latest" \
    --display-vuln-findings="enabled" \
    --out-sbom="./sbom.json" \
    --out-scan="inspector_scan_.json" \
    --out-scan-csv="inspector_scan_.csv" \
    --out-scan-markdown="inspector_scan_.md" \
    --out-dockerfile-scan-csv="inspector_dockerfile_scan_.csv" \
    --out-dockerfile-scan-md="inspector_dockerfile_scan_.md" \
    --sbomgen-version="1.4.0"

