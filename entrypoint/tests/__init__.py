import logging


logger = logging.getLogger()
logger.setLevel(logging.ERROR)

handler = logging.StreamHandler()
handler.setLevel(logging.ERROR)
