FROM public.ecr.aws/amazonlinux/amazonlinux:latest
 
RUN dnf install python3 aws-cli -y

COPY ./entrypoint . 
RUN chmod 0500 /main.py

ENTRYPOINT ["/main.py"]

# note: don't set a WORKDIR in this image, it conflicts with github actions:
# https://docs.github.com/en/actions/creating-actions/dockerfile-support-for-github-actions#workdir
