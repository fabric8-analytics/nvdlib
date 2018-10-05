import logging

from nvdlib import config
from nvdlib.__about__ import __version__


logger = logging.getLogger(name=__name__)

logger_formatter = logging.Formatter('%(asctime)s [%(levelname)s]: %(message)s')

logger_stream_handler = logging.StreamHandler()
logger_stream_handler.setFormatter(logger_formatter)


logger.info("Logging has been set up.")


def set_logging_level(level):
    """Set logging level."""
    level = level or logger.setLevel(config.DEFAULT_LOGGING_LEVEL)

    logging.getLogger(__name__).setLevel(level)


def set_logging_handler(handler=None):
    """Set logging handler.

    If no handler is provided, the default one is set"""
    if handler:
        logger.addHandler(handler)

    else:
        logger.addHandler(logger_stream_handler)


def get_logging_handler():
    """Get default nvdlib logging handler."""
    return logger_stream_handler
import logging

from nvdlib import config
from nvdlib.__about__ import __version__


logger = logging.getLogger(name=__name__)

logger_formatter = logging.Formatter('%(asctime)s [%(levelname)s]: %(message)s')

logger_stream_handler = logging.StreamHandler()
logger_stream_handler.setFormatter(logger_formatter)


logger.info("Logging has been set up.")


def set_logging_level(level):
    """Set logging level."""
    level = level or logger.setLevel(config.DEFAULT_LOGGING_LEVEL)

    logging.getLogger(__name__).setLevel(level)


def set_logging_handler(handler=None):
    """Set logging handler.

    If no handler is provided, the default one is set"""
    if handler:
        logger.addHandler(handler)

    else:
        logger.addHandler(logger_stream_handler)


def get_logging_formatter():
    """Get default nvdlib logging formatter."""
    return logger_formatter


def get_logging_handler():
    """Get default nvdlib logging handler."""
    return logger_stream_handler

