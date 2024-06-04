import logging
import os
import platform
import shutil
import subprocess
import urllib.request
import zipfile


def get_sbomgen_url(os_name: str = "Linux", cpu_arch: str = "amd64", version: str = "latest") -> str:
    """
    get_sbomgen_url constructs a URL for sbomgen.
    This function does not validate the URL is
    correct and functional
    :param os_name: the current operating system name; the only supported value is 'Linux'
    :param cpu_arch: the current cpu architecture; only 'amd64' and 'arm64' are supported
    :param version: the current sbomgen version; valid choices are 'latest', '1.0.0', or '1.1.0'
    :return: returns a URL on success or empty string ("") on failure
    """

    if os_name != "Linux":
        return ""

    valid_cpu_architectures = ['amd64', 'arm64']
    if cpu_arch not in valid_cpu_architectures:
        return ""

    if cpu_arch == "amd64":
        return f"https://amazon-inspector-sbomgen.s3.amazonaws.com/{version}/linux/amd64/inspector-sbomgen.zip"

    elif cpu_arch == "arm64":
        return f"https://amazon-inspector-sbomgen.s3.amazonaws.com/{version}/linux/arm64/inspector-sbomgen.zip"

    else:
        return ""


def download_sbomgen(url: str, dst: str) -> str:
    """
    download a file from the provided url and write the file to the path specified by dst
    :param url: the url to the file; a sbomgen url is expected
    :param dst: the filepath to write the downloaded content to
    :return: returns 'dst' on success and an empty string on failure ("")
    """

    if not url.startswith("https://amazon-inspector-sbomgen.s3.amazonaws.com/"):
        return ""

    try:
        logging.debug(f"downloading sbomgen from url: {url}")
        urllib.request.urlretrieve(url=url, filename=dst)
        return dst
    except Exception as e:
        logging.error(e)
        return ""


def extract_sbomgen(src: str, dst: str) -> str:
    """
    extracts a zip file
    :param src: path to the file you wish to unzip
    :param dst: path where unzipped contents should be written
    :return: returns 'dst' on success and an empty string on failure ("")
    """
    try:
        z = zipfile.ZipFile(src, "r")
        z.extractall(dst)
        z.close()
        return dst

    except Exception as e:
        logging.error(e)
        return ""


def find_file_in_dir(file_name: str, dir_to_search: str) -> str:
    """
    look for a file in a directory
    :param file_name: the file you wish to find
    :param dir_to_search: the directory you wish to search
    :return: returns the path to the file on success and an empty string ("") on failure
    """

    for root, dirs, files in os.walk(dir_to_search):
        if file_name in files:
            path = os.path.join(root, file_name)
            return path

    return ""


def install_sbomgen(sbomgen_path: str, install_path: str) -> str:
    try:
        shutil.move(sbomgen_path, install_path)
        os.chmod(install_path, 0o500)  # read and execute perms for file owner
    except Exception as e:
        logging.error(e)
        return ""

    # verify success
    if platform == "Linux":
        cmd = [install_path, "--version"]
        out = subprocess.run(cmd, capture_output=True, text=True)
        if out.returncode != 0:
            logging.error(out.stderr)
            return ""

    return install_path


sbomgen_install_path = ""


def set_sbomgen_install_path(path):
    global sbomgen_install_path
    sbomgen_install_path = path


def get_sbomgen_install_path():
    global sbomgen_install_path
    return sbomgen_install_path
