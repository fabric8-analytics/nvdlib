"""Selector to query collections of documents."""

import re
import typing


from nvdlib import utils


def match(pattern: typing.Union[str, int]) -> typing.Callable:

    def _match(obj: object, attr: str):
        value = utils.rgetattr(obj, attr)

        if isinstance(pattern, str):
            return re.match(pattern, str(value))
        else:
            return pattern == value

    return _match


def search(pattern: typing.Union[str, int]) -> typing.Callable:

    def _search(obj: object, attr: str):
        value = utils.rgetattr(obj, attr)

        if isinstance(pattern, str):
            return re.search(pattern, str(value))
        else:
            return pattern == value

    return _search


def contains(self):
    pass


def in_range(self, start: int = 0, stop: int = None, step: int = 1):
    pass


def in_date_range(self, start: int = 0, stop: int = None, step: int = None):
    pass
