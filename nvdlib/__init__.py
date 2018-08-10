from . import config

import logging


logger = logging.getLogger(name=__name__)
logger.setLevel(config.DEFAULT_LOGGING_LEVEL)

logger_formatter = logging.Formatter('%(asctime)s [%(levelname)s]: %(message)s')

logger_stream_handler = logging.StreamHandler()
logger_stream_handler.setFormatter(logger_formatter)

logger.addHandler(logger_stream_handler)

logger.info("Logging has been set up.")


def set_logging_level(level):
    logging.getLogger(__name__).setLevel(level)


__version__ = 0.3
