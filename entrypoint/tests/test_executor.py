import sys
import unittest

from entrypoint import executor


class TestExecutor(unittest.TestCase):

    def test_invoke_command(self):
        python = sys.executable
        args = ["-c", "1", " ", "+", " ", "1"]
        got = executor.invoke_command(python, args)
        want = 0
        self.assertEqual(want, got)
