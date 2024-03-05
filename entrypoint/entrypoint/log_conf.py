import logging


class LogFormatter(logging.Formatter):
    def format(self, record):
        """
        formats console logs following this pattern:
            level=debug msg="this is a debug log" file="test_foo.py:11
            level=info msg="this is a info log" file="test_foo.py:11

        this pattern is intended to match the format of sbomgen's console logs
        """
        log_time = self.formatTime(record, "%Y-%m-%d %H:%M:%S")
        log_level = record.levelname.lower()
        log_msg = record.getMessage()
        log_file = f'{record.filename}:{record.lineno}'
        s = f'time="{log_time}" level={log_level} msg="{log_msg}" file="{log_file}"'
        return s


def init(enable_verbose: bool):
    """
    init configures the system's log level and
    format
    :param enable_verbose: if true, set the log level to DEBUG, else INFO
    """
    logger = logging.getLogger()
    handler = logging.StreamHandler()

    if enable_verbose:
        logger.setLevel(logging.DEBUG)
        handler.setLevel(logging.DEBUG)
    else:
        logger.setLevel(logging.INFO)
        handler.setLevel(logging.INFO)

    handler.setFormatter(LogFormatter())
    logger.addHandler(handler)
