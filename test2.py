import logging

class First:
    def __init__(self):
        self.xyi = 1234567
        self.logger = logging.getLogger('1.log')
        self.logger.setLevel(logging.DEBUG)


class CustomFormatter(logging.Formatter):
    yellow = "\033[33m"
    bright_yellow = "\033[93m"
    red = "\033[31m"
    bright_red = "\033[91m"

    bold = "\033[1m"
    reset = "\033[0m"

    date = "%(asctime)s.%(msecs)03d"
    level = " | %(levelname)s"
    message = " %(message)s"

    FORMATS = {
        logging.DEBUG: bold + date + bright_yellow + level + 4 * ' ' + '|' + message + reset,
        logging.INFO: bold + date + level + 5 * ' ' + '|' + message + reset,
        logging.WARNING: bold + date + yellow + level + 2 * ' ' + '|' + message + reset,
        logging.ERROR: bold + date + red + level + 4 * ' ' + '|' + message + reset,
        logging.CRITICAL: bold + date + bright_red + level + ' ' + '|' + message + reset
    }

    def format(self, record):
        log_fmt = self.FORMATS.get(record.levelno)
        formatter = logging.Formatter(log_fmt, datefmt='%H:%M:%S')
        return formatter.format(record)

logging.Formatter(datefmt='%H:%M:%S')
handler = logging.StreamHandler()
handler.setFormatter(CustomFormatter())

logger = logging.getLogger()
logger.setLevel(logging.INFO)
logger.addHandler(handler)

logger.info (1234)
logger.warn(123456)
logger.critical(123456)