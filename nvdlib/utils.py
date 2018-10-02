"""Module containing utilities for nvdlib package."""

import hashlib
import operator
import typing

from collections import Mapping
from prettyprinter import pprint

# NOTE: Victims does not support ``[<>]`` regex
SYMBOLS = ['==', '<', '<=', '>=', '>']
OPERATORS = [
    operator.eq, operator.lt, operator.le, operator.ge, operator.gt,
]
OPERATOR_DICT = dict(zip(SYMBOLS, OPERATORS))


def dictionarize(obj) -> dict:

    array_types = [list, set, tuple]

    def _dictionarize(out_dict: dict, **kwargs) -> dict:
        dct = out_dict or dict()

        for key, value in kwargs.items():
            # replace dashes by underscores JIC
            key = key.replace('-', '_')
            if getattr(value, '_fields', None) or hasattr(value, '_asdict'):
                dct[key] = _dictionarize({}, **value._asdict())
            elif isinstance(value, typing.Mapping):
                dct[key] = _dictionarize({}, **value)
            elif any([isinstance(value, array) for array in array_types]):
                dct[key] = dictionarize(value)
            else:
                dct[key] = value

        return dct

    if getattr(obj, '_fields', None) or hasattr(obj, '_asdict'):
        _call = lambda: _dictionarize({}, **obj._asdict())
    elif isinstance(obj, typing.Mapping):
        _call = lambda: _dictionarize({}, **obj)
    elif any([isinstance(obj, array) for array in array_types]):
        _call = lambda: [
            dictionarize(item) for item in obj
        ]
    else:
        _call = lambda: obj

    return _call()


class AttrDict(Mapping):
    """A class to convert a nested Dictionary into an object with key-values
    accessibly using attribute notation (AttributeDict.attribute) instead of
    key notation (Dict["key"]).

    This class recursively sets Dicts to objects, allowing to recurse down
    the nested dicts (like: AttributeDict.attr.attr)
    """
    def __init__(self, **entries):
        for key, value in entries.items():
            # replace dashes by underscores JIC
            key = key.replace('-', '_')
            if getattr(value, '_fields', None):
                self.__dict__[key] = AttrDict(**dict(value._asdict()))
            elif type(value) is dict:
                self.__dict__[key] = AttrDict(**value)
            else:
                self.__dict__[key] = value

    def __iter__(self):
        for k in self.__dict__:
            yield k

    def __len__(self):
        return len(self.__dict__)

    def __str__(self):
        return self.__dict__.__str__()

    def __repr__(self):
        return self.__dict__.__repr__()

    def __getitem__(self, key):
        """
        Provides dict-style access to attributes
        """
        return getattr(self, key)

    def pretty(self):
        pprint(dictionarize(self))


def get_victims_notation(version_tuple: typing.Sequence) -> list:
    """Maps version range tuple to corresponding victims string notation.

    NOTE: This is pseudo-victims notations, as original victims only permits
    inclusive interval boundaries.

    Assumes arguments ``version_range`` is a tuple or a sequence
    ``(versionExact, versionEndExcluding, versionEndIncluding, versionStartIncluding, versionEndExcluding)``


    :returns: str, victims notation of version ranges (see https://github.com/victims/victims-cve-db)
    """
    if len(version_tuple) != len(SYMBOLS) or len(version_tuple) > 5:
        print(version_tuple)
        raise AttributeError("shape of ``version_tuple`` does not match shape of ``SYMBOLS``."
                             " Expected shapes (5,) == (5,), got: %r != %r" % (len(version_tuple), len(SYMBOLS)))

    if not any(version_tuple):
        victims_notation = None  # undefined

    else:
        indices = [i for i, val in enumerate(version_tuple) if val is not None]
        victims_notation = [
            str(SYMBOLS[i]) + str(version_tuple[i]) for i in indices
        ]

    return victims_notation


def compute_sha256(fpath):
    sha256 = hashlib.sha256()
    with open(fpath, 'rb') as f:
        while True:
            data = f.read(4096)
            if not data:
                break
            sha256.update(data)
    return sha256.hexdigest().lower()


def rhasattr(obj, attr: str) -> bool:
    # check for and array
    if isinstance(obj, list):
        if not obj:  # empty list
            return False

        return any(rhasattr(item, attr) for item in obj)

    try:
        left, right = attr.split('.', 1)

    except ValueError:
        return hasattr(obj, attr)

    return rhasattr(getattr(obj, left), right)


def rgetattr(obj,
             attr: str,
             repl_missing=None,
             raise_if_missing=False) -> typing.Any:

    if isinstance(obj, list):
        if not obj:  # empty list
            return None

        return [
            rgetattr(item, attr, repl_missing, raise_if_missing)
            for item in obj
        ]

    try:
        left, right = attr.split('.', 1)
    except ValueError:

        try:
            return getattr(obj, attr)

        except AttributeError as exc:
            # handle inconsistency
            if raise_if_missing:
                raise exc

            return repl_missing

    return rgetattr(getattr(obj, left), right, repl_missing, raise_if_missing)
