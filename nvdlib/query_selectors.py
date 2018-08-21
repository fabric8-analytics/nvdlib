"""Selector to query collections of documents."""

import re
import typing

import logging

from datetime import datetime

from nvdlib import utils


_LOGGER = logging.getLogger(__name__)


def match(pattern: typing.Union[str, int], full_match=True, **kwargs) -> typing.Callable:

    def _match(obj: object, attr: str):
        value = utils.rgetattr(obj, attr)

        search_space = [value]
        if isinstance(value, list):
            search_space = value

        found = False
        for val in search_space:

            if val is None:
                continue

            # type adaptation only if val is int
            if isinstance(val, int):
                val = type(pattern)(val)

            if not isinstance(pattern, type(val)):
                raise TypeError(f"Type mismatch: pattern of type `{type(pattern)}`, value of type `{type(val)}`")

            if isinstance(pattern, str):
                if full_match:
                    found = re.fullmatch(pattern, val, **kwargs)
                else:
                    found = re.match(pattern, val, **kwargs)
            else:
                found = pattern == val

            if found:
                break

        return found

    return _match


def search(pattern: typing.Union[str, int], **kwargs) -> typing.Callable:

    if not isinstance(pattern, str):
        raise TypeError(f"Search matching is only possible for string patterns, got: `{type(pattern)}`.")

    def _search(obj: object, attr: str):
        value = utils.rgetattr(obj, attr)

        search_space = [value]
        if isinstance(value, list):
            search_space = value

        found = False
        for val in search_space:

            if val is None:
                continue

            # type adaptation only if val is int
            if isinstance(val, int):
                val = type(pattern)(val)

            if not isinstance(pattern, type(val)):
                raise TypeError(f"Type mismatch: pattern of type `{type(pattern)}`, value of type `{type(val)}`")

            found = re.search(pattern, val, **kwargs)

            if found:
                break

        return found

    return _search


def gt(limit: typing.Union[str, int, float]):

    expected_types = [str, int, float]
    if not any([isinstance(limit, t) for t in expected_types]):
        raise TypeError(f"`limit` expected to be of type {typing.Union[int, float]}, got: `{type(limit)}`")

    def _gt(obj: object, attr: str):
        value = utils.rgetattr(obj, attr)

        search_space = [value]
        if isinstance(value, list):
            search_space = value

        for val in search_space:

            if val is None:
                continue

            if val.__gt__(limit):
                return True

        return False

    return _gt


def lt(limit: typing.Union[str, int, float]):

    expected_types = [str, int, float]
    if not any([isinstance(limit, t) for t in expected_types]):
        raise TypeError(f"`limit` expected to be of type {typing.Union[int, float]}, got: `{type(limit)}`")

    def _lt(obj: object, attr: str):
        value = utils.rgetattr(obj, attr)

        search_space = [value]
        if isinstance(value, list):
            search_space = value

        for val in search_space:

            if val is None:
                continue

            if val.__lt__(limit):
                return True

        return False

    return _lt


def in_range(high: typing.Union[str, int, datetime], low: typing.Union[str, int, datetime] = None):

    if low and high <= low:
        raise ValueError(f"`high` must be > `low`: {high} <= {low}")

    def _in_range(obj: object, attr: str):
        value = utils.rgetattr(obj, attr)

        search_space = [value]
        if isinstance(value, list):
            search_space = value

        res = False
        for val in search_space:

            if val is None:
                continue

            if low is not None:
                res = low <= val < high
            else:
                res = val < high

            if res:
                break

        return res

    return _in_range
