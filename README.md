# Vulnerability Scan GitHub Action for Amazon Inspector

Amazon Inspector is a vulnerability management service that scans AWS workloads
and [CycloneDX SBOMs](https://cyclonedx.org/) for known software vulnerabilities.

This GitHub Action allows you to scan supported artifacts for software vulnerabilities using Amazon Inspector from your
GitHub Actions workflows.

An active AWS account is required to use this action.

## Overview

This action works by first generating a CycloneDX software bill of materials (SBOM) for the provided artifact. The SBOM is then sent to Amazon Inspector and scanned for known vulnerabilities.

This action can scan the following artifact types for vulnerabilities:

1. Files and directories in your GitHub repository
2. Container images
3. Compiled Go and Rust binaries (*stripped and obfuscated binaries are not supported*)
4. Archives *(.zip, .tar, .tar.gz)*

For more information, please refer to Amazon Inspector's supported [artifacts](https://docs.aws.amazon.com/inspector/latest/user/sbom-generator.html) and [container operating systems](https://docs.aws.amazon.com/inspector/latest/user/supported.html#supported-os-ecr).

To learn more about Amazon Inspector, as well as Inspector's free trial and pricing model, please see the links below:

1. https://aws.amazon.com/inspector/
2. https://aws.amazon.com/inspector/pricing/?nc=sn&loc=3


## Prerequisites

1. **Required:** You must have an active AWS account to use this action. Guidance on creating an AWS account is
   provided [here](https://docs.aws.amazon.com/inspector/latest/user/configure-cicd-account.html).

2. **Required:** You must have read access to the **InspectorScan:ScanSbom**
   API. [See here for configuration instructions](https://docs.aws.amazon.com/inspector/latest/user/configure-cicd-account.html#cicd-iam-role)
   .

3. **Required:** You must configure AWS authentication for use in GitHub action workflows. We recommend
   using [configure-aws-credentials](https://github.com/marketplace/actions/configure-aws-credentials-action-for-github-actions)
   for this purpose.

4. **Required:** Create a GitHub Actions workflow if you do not already have one. Guidance on doing so is
   available [here](https://docs.github.com/en/actions/quickstart).

5. **Required:** Configure Dependabot to keep this action up to date so you receive the latest bug fixes and security
   updates. Guidance on doing so is
   available [here](https://docs.github.com/en/code-security/dependabot/working-with-dependabot/keeping-your-actions-up-to-date-with-dependabot#enabling-dependabot-version-updates-for-actions)
   .

6. *Optional:* Configure container registry authentication if needed. GitHub Actions are available for this purpose
   including [Docker Login](https://github.com/marketplace/actions/docker-login).

## Usage

### Quick Start

Perform the following steps to quickly add this action to your GitHub Actions pipeline:

1. Copy and paste the following YAML block into your workflow file.

   **Read through this workflow definition and make changes to suit your environment**:

    ```yaml
   name: Scan artifact with Amazon Inspector
   on: [push]
   jobs:
     daily_job:
       runs-on: ubuntu-latest

       # change this to match your GitHub Secrets environment
       environment:
         name: your_github_secrets_environment

       steps:

         # modify this block based on how you authenticate to AWS
         # make sure you have permission to access the Inspector ScanSbom API
         # https://docs.aws.amazon.com/inspector/latest/user/configure-cicd-account.html#cicd-iam-role
         - name: Configure AWS credentials
           uses: aws-actions/configure-aws-credentials@v4
           with:
             aws-region: "us-east-1"
             role-to-assume: "arn:aws:iam::<AWS_ACCOUNT_ID>:role/<IAM_ROLE_NAME>"

         # Check out your repository if needed
         - name: Checkout this repository
           uses: actions/checkout@v4

         # modify this block to scan your intended artifact
         - name: Inspector Scan
           id: inspector
           uses: aws-actions/vulnerability-scan-github-action-for-amazon-inspector@v1
           with:
             # change artifact_type to either 'repository', 'container', 'binary', or 'archive'.
             artifact_type: 'repository'

             # change artifact_path to the file path or container image you would like to scan.
             # File paths should be relative to your root project directory.
             # For containers, this action accepts 'docker pull'-style references to containers,
             # such as 'alpine:latest' or a file path to an image exported as TAR using docker save.
             artifact_path: './'

             # If enabled, this setting will display Inspector's vulnerability scan findings
             # as a GitHub actions step summary. See here for an example step summary:
             # https://github.com/aws-actions/vulnerability-scan-github-action-for-amazon-inspector/actions/runs/8800085041
             display_vulnerability_findings: "enabled"

             # Set vulnerability thresholds; if the number of vulnerabilities is
             # equal to or greater than any of the specified thresholds, this
             # action will set the 'vulnerability_threshold_exceeded'
             # output flag to 1.
             critical_threshold: 1
             high_threshold: 1
             medium_threshold: 1
             low_threshold: 1
             other_threshold: 1

             # Additional input arguments are available to control scan behavior.
             # See 'action.yml' for additional input/output options.


         # The following steps illustrate how to
         # display scan results in the GitHub Actions job terminal.
         - name: Display CycloneDX SBOM (JSON)
           run: cat ${{ steps.inspector.outputs.artifact_sbom }}

         - name: Display Inspector vulnerability scan results (JSON)
           run: cat ${{ steps.inspector.outputs.inspector_scan_results }}

         - name: Display Inspector vulnerability scan results (CSV)
           run: cat ${{ steps.inspector.outputs.inspector_scan_results_csv }}

         - name: Display Inspector vulnerability scan results (Markdown)
           run: cat ${{ steps.inspector.outputs.inspector_scan_results_markdown }}


         # The following steps illustrate how to
         # upload scan results as a GitHub actions job artifact
         - name: Upload Scan Results
           uses: actions/upload-artifact@v4
           with:
             name: Inspector Vulnerability Scan Artifacts
             path: |
               ${{ steps.inspector.outputs.inspector_scan_results }}
               ${{ steps.inspector.outputs.inspector_scan_results_csv }}
               ${{ steps.inspector.outputs.artifact_sbom }}
               ${{ steps.inspector.outputs.inspector_scan_results_markdown }}


           # This step illustrates how to add custom logic if
           # the vulnerability threshold is exceeded. This example
           # simply prints the 'vulnerability_threshold_exceeded' value
           # to the GitHub actions job terminal.
           # Replace 'echo' with 'exit' if you want to fail the job.
         - name: On vulnerability threshold exceeded
           run: echo ${{ steps.inspector.outputs.vulnerability_threshold_exceeded }}
    ```

2. Save your workflow file, then git commit / git push the workflow to GitHub.

GitHub should automatically run your new workflow; review its results and make any needed changes to the input and
output arguments.

For additional examples, see [this repository's workflow definitions](.github/workflows/).

### Configuring Vulnerability Scan Outputs

By default, this action only displays the number of vulnerabilities detected in the GitHub Actions job terminal. Detailed findings are optional and configurable as JSON, CSV, or Markdown. In addition, an artifact inventory is available as a CycloneDX JSON file.

The below example shows how to enable action outputs in various locations and formats.

**Exercise caution to ensure you do not accidentally post vulnerability information to untrusted viewers.**

```yaml
- name: Scan container
  id: inspector
  uses: aws/vulnerability-scan-github-action-for-amazon-inspector@v1
  with:
    artifact_type: 'container'
    artifact_path: 'ubuntu:14.04'
    display_vulnerability_findings: "enabled"

# Display Inspector results in the GitHub Actions terminal
- name: Display CycloneDX SBOM (JSON)
  run: cat ${{ steps.inspector.outputs.artifact_sbom }}

- name: Display Inspector vulnerability scan results (JSON)
  run: cat ${{ steps.inspector.outputs.inspector_scan_results }}

- name: Display Inspector vulnerability scan results (CSV)
  run: cat ${{ steps.inspector.outputs.inspector_scan_results_csv }}

- name: Display Inspector vulnerability scan results (markdown)
  run: cat ${{ steps.inspector.outputs.inspector_scan_results_markdown }}


# Upload Inspector outputs as a .zip that can be downloaded
# from the GitHub actions job summary page.
- name: Upload Scan Results
  id: inspector
  uses: actions/upload-artifact@v4
  with:
  path: |
    ${{ steps.inspector.outputs.inspector_scan_results }}
    ${{ steps.inspector.outputs.inspector_scan_results_csv }}
    ${{ steps.inspector.outputs.artifact_sbom }}
```

### Configuring Vulnerability Thresholds

This action allows the user to set vulnerability thresholds.

Vulnerability thresholds can be used to support custom logic, such as failing the workflow if any vulnerabilities are
found.

The example below shows how to set up vulnerability thresholds and fail the job when the threshold is exceeded:

```yaml
- name: Invoke Amazon Inspector Scan
  id: inspector
  uses: aws/vulnerability-scan-github-action-for-amazon-inspector@v1
  with:
    artifact_type: 'repository'
    artifact_path: './'
    display_vulnerability_findings: "enabled"

    # If the number of vulnerabilities equals or exceeds
    # any of the specified vulnerability thresholds, this action
    # sets a flag, 'vulnerability_threshold_exceeded' to 1, else 0.
    # To ignore thresholds for a given severity, set its value to 0.
    # This example sets 'vulnerability_threshold_exceeded' flag if
    # one or more criticals, highs, or medium severity vulnerabilities
    # are found; lows and other type vulnerabilities will not set
    # the 'vulnerability_threshold_exceeded' flag.
    critical_threshold: 1
    high_threshold: 1
    medium_threshold: 1
    low_threshold: 0
    other_threshold: 0

# Fail the job with 'exit 1' if vuln threshold flag is set
- name: On vulnerability threshold exceeded
  run: exit ${{ steps.inspector.outputs.vulnerability_threshold_exceeded }}
```

### Build and Scan Container Images

This action supports a common use case that entails building a container image, scanning the built image for
vulnerabilities, and optionally, failing the workflow before the image is deployed to a container registry or elsewhere.

We provide an example of this workflow below. You must modify this workflow to suit your environment:

```yaml
name: Build & Scan Container Image

on: [ push ]

jobs:
  build:
    name: Build docker image
    runs-on: ubuntu-latest
    environment:
      # change this to match your GitHub secrets environment
      name: plugin-development

    steps:
      # checkout the repository containing our Dockerfile
      - name: Checkout this repository
        uses: actions/checkout@v4

      # Setup prerequisites for docker/build-push-action
      - name: Set up docker build prereqs (QEMU)
        uses: docker/setup-qemu-action@v3

      - name: Set up docker build prereqs (Buildx)
        uses: docker/setup-buildx-action@v3

      # build the image you wish to scan
      - name: Build Docker image
        uses: docker/build-push-action@v5
        with:
          context: .
          file: ./Dockerfile
          push: false
          tags: app:latest
          load: true

      # setup your AWS credentials
      - name: Configure AWS credentials
        uses: aws-actions/configure-aws-credentials@v4
        with:
          aws-region: "us-east-1"
          role-to-assume: "arn:aws:iam::<AWS_ACCOUNT_ID>:role/<IAM_ROLE_NAME>"

      - name: Scan built image with Inspector
        uses: aws-actions/vulnerability-scan-github-action-for-amazon-inspector@v1
        id: inspector
        with:
          artifact_type: 'container'
          artifact_path: 'app:latest' # make sure this matches the image you built
          critical_threshold: 1
          high_threshold: 1
          medium_threshold: 1
          low_threshold: 1
          other_threshold: 1
          # set additional arguments as needed

      - name: Fail job if vulnerability threshold is exceeded
        run: exit ${{ steps.inspector.outputs.vulnerability_threshold_exceeded }}

        # add any additional steps for deploying your image
```

## Action Inputs and Outputs

The following input and output options are provided by this action. See [action.yml](./action.yml) for more detail.

### Input Options

| **Name** | **Description**                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                          | **Required** | **Default** |
|---|--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|---|---|
| artifact_type | The artifact you would like to scan with Amazon Inspector. Valid choices are "repository", "container", "binary", or "archive".                                                                                                                                                                                                                                                                                                                                                                                                                                                                                          | True | repository |
| artifact_path | The file path to the artifact you would like to scan with Amazon Inspector. File paths are relative to the root project directory. If scanning a container image, you must provide a value that follows the docker pull convention. For example, "alpine:latest", or a path to an image exported as tarball using "docker save".                                                                                                                                                                                                                                                                                         | True | ./ |
| display_vulnerability_findings | If set to "enabled", the action will display detailed vulnerability findings in the action summary page; see here for an example: https://github.com/aws-actions/vulnerability-scan-github-action-for-amazon-inspector/actions/runs/8742638284/attempts/1#summary-23991378549                                                                                                                                                                                                                                                                                                                                            | True | disabled |
| output_sbom_path | The destination file path for the generated SBOM.                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                        | False | ./sbom_${{ github.run_id }}.json |
| output_inspector_scan_path | The destination file path for Inspector's vulnerability scan (JSON format).                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                              | False | inspector_scan_${{ github.run_id }}.json |
| output_inspector_scan_path_csv | The destination file path for Inspector's vulnerability scan (CSV format).                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                               | False | inspector_scan_${{ github.run_id }}.csv |
| output_inspector_scan_path_markdown | The destination file path for Inspector's vulnerability scan (markdown format).                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                          | False | inspector_scan_${{ github.run_id }}.md |
| sbomgen_version | The inspector-sbomgen version you wish to use for SBOM generation. See here for more info: https://docs.aws.amazon.com/inspector/latest/user/sbom-generator.html                                                                                                                                                                                                                                                                                                                                                                                                                                                         | False | latest |
| critical_threshold | Specifies the number of critical vulnerabilities needed to set the 'vulnerability_threshold_exceeded' flag.                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                              | False | 0 |
| high_threshold | Specifies the number of high vulnerabilities needed to set the 'vulnerability_threshold_exceeded' flag.                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                  | False | 0 |
| medium_threshold | Specifies the number of medium vulnerabilities needed to set the 'vulnerability_threshold_exceeded' flag.                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                | False | 0 |
| low_threshold | Specifies the number of low vulnerabilities needed to set the 'vulnerability_threshold_exceeded' flag.                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                   | False | 0 |
| other_threshold | Specifies the number of other vulnerabilities needed to set the 'vulnerability_threshold_exceeded' flag.                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                 | False | 0 |
| scanners | Specifies the file scanners that you would like inspector-sbomgen to execute. By default, inspector-sbomgen will try to run all file scanners that are applicable to the target artifact. If this argument is set, inspector-sbomgen will only execute the specified file scanners. Provide your input as a single string. Separate each file scanner with a comma. For example: scanners: dpkg,python-requirements,javascript-npm-packagelock To view a list of available file scanners, execute 'inspector-sbomgen list-scanners'. See here for more info: https://docs.aws.amazon.com/inspector/latest/user/sbom-generator.html | False | '' |
| skip_scanners | Specifies a list of file scanners that should NOT be executed; this argument cannot be combined with 'scanners'. If this argument is set, inspector-sbomgen will execute all file scanners except those you specified. Provide your input as a single string. Separate each file scanner with a comma. For example: skip_scanners: 'binaries,alpine-apk,dpkg,php'To view a list of available file scanners, execute 'inspector-sbomgen list-scanners'. See here for more info: https://docs.aws.amazon.com/inspector/latest/user/sbom-generator.html                                                                     | False | '' |
| skip_files | Specifies one or more files and/or directories that should NOT be inventoried. Separate each file with a comma and enclose the entire string in double quotes, for example: skip_files: "./media,/tmp/foo/,/bar/my_program"                                                                                                                                                                                                                                                                                                                                                                                              | False | '' |
| timeout | Specifies a timeout in seconds. If this timeout is exceeded, the action will gracefully conclude and present any findings discovered up to that point. Default value is 600 seconds or 10 minutes.                                                                                                                                                                                                                                                                                                                                                                                                                       | False | 600 |

### Output Options

| **Name** | **Description** |
|---|---|
| artifact_sbom | The file path to the artifact's software bill of materials. |
| inspector_scan_results | The file path to the Inspector vulnerability scan findings in JSON format. |
| inspector_scan_results_csv | The file path to the Inspector vulnerability scan findings in CSV format. |
| inspector_scan_results_markdown | The file path to the Inspector vulnerability scan findings in markdown format. |
| vulnerability_threshold_exceeded | This variable is set to 1 if any vulnerability threshold was exceeded, otherwise it is 0. This variable can be used to trigger custom logic, such as failing the job if vulnerabilities were detected. |

## Get Help

For general questions about this action, please post your question to the project's discussion page:

- https://github.com/aws-actions/vulnerability-scan-github-action-for-amazon-inspector/discussions

You may also consider exploring these resources for additional help with AWS products and services:

- https://repost.aws/knowledge-center/get-aws-help

## Bugs

If you encountered a bug, please open a GitHub issue:

- https://github.com/aws-actions/vulnerability-scan-github-action-for-amazon-inspector/issues/new/choose

## Security

See [CONTRIBUTING](CONTRIBUTING.md#security-issue-notifications) for more information.

## License

This project is licensed under the MIT license.

Copyright 2024 Amazon.com, Inc. or its affiliates. All Rights Reserved
