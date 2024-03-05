import sys
import unittest

from entrypoint import cli


class TestCLI(unittest.TestCase):

    def test_cli(self):
        argv = ["--artifact-type", "container"]
        args = cli.init(argv)
        self.assertEqual(args.artifact_type, "container")
        return


if __name__ == "__main__":
    unittest.main()
