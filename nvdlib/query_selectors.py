"""Selector to query collections of documents."""

import re
import typing

import logging

from datetime import datetime
from functools import wraps

from nvdlib import utils, config

# TODO: Implement `or_` and `and_` selector operators
# TODO: Consider implementing `any`, `all`, `exists`, and `apply` selectors, which would enable more customization

_LOGGER = logging.getLogger(__name__)


def _warn_or_raise(msg):
    """Log warning or raise TypeError based on TYPE_CHECK_LEVEL value."""
    if config.TYPE_CHECK_LEVEL < 2:
        _LOGGER.warning(msg)
    else:
        raise TypeError(msg)


def selector(fn: callable) -> typing.Callable:  # noqa: D401
    """Wrapper for specific selectors."""
    @wraps(fn)
    def _arg_wrapper(*args, **kwargs):

        @wraps(fn)
        def _fn_wrapper(obj: object, attr: str):

            attr_value = utils.rgetattr(obj, attr)

            search_space = [attr_value]
            if isinstance(attr_value, list):
                search_space = attr_value

            ret = False
            for value in search_space:

                if value is None:
                    continue

                if isinstance(value, list):
                    ret = any([
                        fn(value=v, *args, **kwargs) for v in value
                    ])

                else:
                    ret = fn(value=value, *args, **kwargs)

                if ret:
                    break

            return ret

        return _fn_wrapper

    return _arg_wrapper


@selector
def match(pattern: typing.Union[str, int],
          full_match=True,
          **kwargs):
    """Compare value to pattern using match."""
    value = kwargs.pop('value')

    # type adaptation only if val is int or float
    if isinstance(value, int) or isinstance(value, float):
        value = type(pattern)(value)

    if config.TYPE_CHECK_LEVEL > 0:
        if not isinstance(pattern, type(value)):
            _warn_or_raise(f"Type mismatch: pattern of type `{type(pattern)}`, value of type `{type(value)}`")

    if isinstance(pattern, str):
        if full_match:
            found = re.fullmatch(pattern, value, **kwargs)
        else:
            found = re.match(pattern, value, **kwargs)
    else:
        found = pattern == value

    return bool(found)


@selector
def search(pattern: typing.Union[str, int],
           **kwargs):
    """Compare value to pattern using search."""
    value = kwargs.pop('value')

    # type adaptation only if value is int
    if isinstance(value, int):
        value = type(pattern)(value)

    if config.TYPE_CHECK_LEVEL > 0:
        if not isinstance(pattern, str):
            _warn_or_raise(f"Search matching is only possible for string patterns, got: `{type(pattern)}`.")

        if not isinstance(pattern, type(value)):
            _warn_or_raise(f"Type mismatch: pattern of type `{type(pattern)}`, value of type `{type(value)}`")

    found = bool(re.search(pattern, value, **kwargs))

    return found


@selector
def gt(limit: typing.Union[str, int, float, datetime], **kwargs):
    """Compare whether given value is greater than given limit."""
    expected_types = [str, int, float, datetime]

    if config.TYPE_CHECK_LEVEL > 0:
        if not any([isinstance(limit, t) for t in expected_types]):
            _warn_or_raise(f"`limit` expected to be any of {expected_types}, got: `{type(limit)}`")

    value = kwargs.pop('value')

    return value.__gt__(limit)


@selector
def ge(limit: typing.Union[str, int, float, datetime], **kwargs):
    """Compare whether given value is greater or equal than given limit."""
    expected_types = [str, int, float, datetime]

    if config.TYPE_CHECK_LEVEL > 0:
        if not any([isinstance(limit, t) for t in expected_types]):
            _warn_or_raise(f"`limit` expected to be any of {expected_types}, got: `{type(limit)}`")

    value = kwargs.pop('value')

    return value.__ge__(limit)


@selector
def lt(limit: typing.Union[str, int, float, datetime], **kwargs):
    """Compare whether given value is lower than given limit."""
    expected_types = [str, int, float, datetime]

    if config.TYPE_CHECK_LEVEL > 0:
        if not any([isinstance(limit, t) for t in expected_types]):
            _warn_or_raise(f"`limit` expected to be any of {expected_types}, got: `{type(limit)}`")

    value = kwargs.pop('value')

    return value.__lt__(limit)


@selector
def le(limit: typing.Union[str, int, float, datetime], **kwargs):
    """Compare whether given value is lower or equal than given limit."""
    expected_types = [str, int, float, datetime]

    if config.TYPE_CHECK_LEVEL > 0:
        if not any([isinstance(limit, t) for t in expected_types]):
            _warn_or_raise(f"`limit` expected to be any of {expected_types}, got: `{type(limit)}`")

    value = kwargs.pop('value')

    return value.__le__(limit)


@selector
def in_(array: typing.Union[list, set], **kwargs):
    """Return whether element is present in the array."""
    if config.TYPE_CHECK_LEVEL > 0:
        if not isinstance(array, list) and not isinstance(array, set):
            _warn_or_raise(f"`array` expected to be list or set, got `{type(array)}`")

    value = kwargs.pop('value')

    return value in array


@selector
def in_range(low: typing.Union[str, int, float, datetime],
             high: typing.Union[str, int, float, datetime],
             **kwargs):
    """Return whether value is present within given range.

    NOTE: Interval boundaries are inclusive.
    """
    expected_types = [str, int, float, datetime]

    if config.TYPE_CHECK_LEVEL > 0:
        if not any([isinstance(low, t) for t in expected_types]):
            _warn_or_raise(f"`low` expected to be any of {expected_types}, got: `{type(low)}`")

        if not any([isinstance(high, t) for t in expected_types]):
            _warn_or_raise(f"`high` expected to be any of {expected_types}, got: `{type(high)}`")

    if low and high <= low:
        raise ValueError(f"`high` must be > `low`: {high} <= {low}")

    value = kwargs.pop('value')

    return low <= value <= high
