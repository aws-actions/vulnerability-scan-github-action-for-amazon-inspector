# This image is intended to test
# rendering of Dockerfile security checks.
# This image has security issues by design
# and should NOT be used for any production
# products or services.
FROM ubuntu:14.04

# IN-DOCKER-004
# Use of apt: 'apt' does not have a stable CLI interface for non-interactive use
RUN apt update -y

# IN-DOCKER-001
# apt-get layer caching: Using apt-get update alone in a RUN statement causes caching issues and subsequent apt-get install instructions to fail.
RUN apt-get update 

# IN-DOCKER-003
# Last USER is root: If a service can run without privileges, use USER to change to a non-root user
USER root

# IN-DOCKER-002
# Avoid installing or using sudo as it has unpredictable TTY and signal-forwarding behavior that can cause problems
RUN apt-get install sudo
RUN sudo whoami

# IN-DOCKER-005-00X 
# Weakened Shell Command Exec Flag: 'apt-get --allow-unauthenticated' installs Advantaged package tool (APT) packages on Debian-based Linux distributions without validating package signatures.
RUN apt-get install vim --allow-unauthenticated -y

# IN-DOCKER-006-00X
# Weakened Environment Variable: 'NPM_CONFIG_STRICT_SSL' is false, disabling TLS certificate validation when 'npm' makes requests to the Node Package Manager registry via https.
ENV NPM_CONFIG_STRICT_SSL=false

ENTRYPOINT ["/bin/bash"]
