import os
import shutil
import tempfile

from unittest import TestCase

from entrypoint import installer


class TestInstaller(TestCase):

    def test_get_sbomgen_url(self):
        got = installer.get_sbomgen_url()
        want = "https://amazon-inspector-sbomgen.s3.amazonaws.com/latest/linux/amd64/inspector-sbomgen.zip"
        self.assertEqual(want, got)

        got = installer.get_sbomgen_url(os_name="Linux", cpu_arch="amd64", version="latest")
        want = "https://amazon-inspector-sbomgen.s3.amazonaws.com/latest/linux/amd64/inspector-sbomgen.zip"
        self.assertEqual(want, got)

        got = installer.get_sbomgen_url(os_name="Linux", cpu_arch="arm64", version="latest")
        want = "https://amazon-inspector-sbomgen.s3.amazonaws.com/latest/linux/arm64/inspector-sbomgen.zip"
        self.assertEqual(want, got)

        got = installer.get_sbomgen_url(os_name="Linux", cpu_arch="amd64", version="1.1.0")
        want = "https://amazon-inspector-sbomgen.s3.amazonaws.com/1.1.0/linux/amd64/inspector-sbomgen.zip"
        self.assertEqual(want, got)

        got = installer.get_sbomgen_url(os_name="Linux", cpu_arch="arm64", version="1.1.0")
        want = "https://amazon-inspector-sbomgen.s3.amazonaws.com/1.1.0/linux/arm64/inspector-sbomgen.zip"
        self.assertEqual(want, got)

        got = installer.get_sbomgen_url(os_name="garbage", cpu_arch="garbage")
        want = ""
        self.assertEqual(want, got)

    def test_install_sbomgen(self):
        # download sbomgen
        url = "https://amazon-inspector-sbomgen.s3.amazonaws.com/latest/linux/amd64/inspector-sbomgen.zip"
        dst = tempfile.gettempdir()
        dst = os.path.join(dst, "inspector-sbomgen.zip")
        got = installer.download_sbomgen(url, dst)
        self.assertEqual(dst, got)

        # unzip sbomgen
        extracted_src = dst
        extracted_dst = os.path.join(tempfile.gettempdir(), "inspector-sbomgen")
        got = installer.extract_sbomgen(extracted_src, extracted_dst)
        self.assertEqual(extracted_dst, got)

        # find sbomgen ELF binary
        sbomgen_path = installer.find_file_in_dir("inspector-sbomgen", extracted_dst)
        got = os.path.basename(sbomgen_path)
        want = "inspector-sbomgen"
        self.assertEqual(want, got)

        # install sbomgen
        install_dst = os.path.join(tempfile.gettempdir(), "installed")
        got = installer.install_sbomgen(sbomgen_path, install_dst)
        self.assertEqual(install_dst, got)

        # test setters and getters
        installer.set_sbomgen_install_path(install_dst)
        got = installer.get_sbomgen_install_path()
        self.assertEqual(install_dst, got)

        # cleanup
        os.remove(dst)
        os.remove(install_dst)
        shutil.rmtree(extracted_dst)
