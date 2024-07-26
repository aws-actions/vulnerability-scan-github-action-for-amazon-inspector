import logging
import unittest

from entrypoint import log_conf


class TestLogConf(unittest.TestCase):

    def setUp(self):
        logger = logging.getLogger()
        # preserve current loglevel before the loglevel is changed by test cases in this class
        self.log_level = logger.level

    def tearDown(self):
        logger = logging.getLogger()
        # restore original loglevel
        logger.setLevel(self.log_level)

    def test_init_verbose(self):
        log_conf.init(enable_verbose=True)
        logger = logging.getLogger()
        want = 10  # DEBUG level
        got = logger.level
        self.assertEqual(want, got)

        # verify we emit debug logs
        with self.assertLogs(level="DEBUG") as l:
            logging.debug("test")

    def test_init_info(self):
        log_conf.init(enable_verbose=False)
        logger = logging.getLogger()
        want = 20  # INFO level
        got = logger.level
        self.assertEqual(want, got)

        # verify we emit info logs
        with self.assertLogs(level="INFO") as l:
            logging.info("test")


if __name__ == "__main__":
    unittest.main()
