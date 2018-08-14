"""Default adapter."""

import atexit
import fcntl
import gc
import os
import re

import datetime
import time

import itertools
import typing

import pickle
import ujson

from nvdlib.adapters.base import BaseAdapter
from nvdlib.selector import Selector


__LOCKS = set()


def register_lock(*fd):
    """Register and lock given file descriptors."""
    global __LOCKS

    for tolock_fd in fd:
        fcntl.flock(tolock_fd, fcntl.LOCK_EX | fcntl.LOCK_NB)

    __LOCKS.add(fd)


def release_lock(*fd):
    """Release locks on given file descriptors and close them."""
    for locked_fd in fd:
        fcntl.flock(locked_fd, fcntl.LOCK_UN)
        # wait for lock to be released
        time.sleep(0.1)

        locked_fd.close()


atexit.register(release_lock, *__LOCKS)


class Document:
    """Forward reference of nvdlib.model.Document class"""


class DefaultAdapter(BaseAdapter):

    STORAGE_BATCH_SIZE = 5000

    def __init__(self, storage: str = None):
        """Initialize DefaultAdapter instance."""
        # run this before any other initialization
        super(DefaultAdapter, self).__init__()

        self._storage = storage

        self._data: typing.List[Document] = [None] * self.STORAGE_BATCH_SIZE
        self._meta: typing.Dict[str, dict] = dict()

        self._meta_fpath = None
        self._meta_fd = None
        self._batches = set()  # set of batch file descriptors

        self._bitmask_size = 32

    def __del__(self):
        """Finalize object destruction."""
        release_lock(*self._batches, self._meta_fd)

    def connect(self, storage: str = None):
        """Connect adapter adapter to a storage."""

        if not any([storage, self._storage]):
            raise ValueError("Storage has not been provided.")

        self._storage = storage or self._storage

        # metadata
        self._meta_fpath = os.path.join(self._storage, '.meta')

        if not os.path.isfile(self._meta_fpath):
            open(self._meta_fpath, 'wb').close()

        self._meta_fd = open(self._meta_fpath, 'r+b')

        register_lock(self._meta_fd)

        # batches
        # read meta and set cursor to the beginning for future usage
        self._meta = ujson.loads(self._meta_fd.read().decode('utf-8') or '{}')

        for value_dict in self._meta.values():

            batch_file = value_dict['batch']
            batch_fpath = os.path.join(self._storage, batch_file)
            batch_fd = open(batch_fpath, 'r+b')

            register_lock(batch_fd)

            self._batches.add(batch_fd)

        return self

    def process(self, data: typing.Iterable["Document"]):
        """Process given data and store in connected storage."""

        batch_size = 0

        for index, document in enumerate(data):
            # noinspection PyUnresolvedReferences
            assert document.cve, f"Invalid document: {document}"
            # noinspection PyUnresolvedReferences
            document_id: str = document.cve.id_

            # store meta pointer to current batch and position
            self._meta[document_id] = {'index': index}
            self._data[index] = document

            batch_size += 1

            if batch_size % self.STORAGE_BATCH_SIZE == 0:
                self.cache()

        self._count = batch_size

        return self

    def select(self, *selectors: Selector, operator: str = 'AND'):
        """Select documents based on given selector."""

    def project(self, *selectors: Selector):
        """Project specific attributes based on given selectors."""

    def filter(self, fn: callable):
        """Filter documents based on function call."""

    def sample(self, size: int = 20):
        """Draw random sample."""

    def dump(self, storage: typing.Any = None):
        """Dump stored data into a storage."""

    def cache(self):
        """Cache stored data."""
        batch_number = len(self._batches)

        year_pattern = r"(?:CVE-)(\d+)(?:-\d+)"

        timestamp = datetime.datetime.now().timestamp()

        years_in_batch = set(map(
            lambda cve_id: re.findall(year_pattern, cve_id)[0],
            self._meta.keys()
        ))

        # year mask
        encoded_bitmask = self._encode(years_in_batch)
        # construct file name
        dump_file = f"{encoded_bitmask}.{batch_number}.{timestamp}"
        dump_path = os.path.join(self._storage, dump_file)

        for key in self._meta.keys():
            self._meta[key].update({'batch': dump_file})

        # dump batch
        dump_fd = open(dump_path, 'wb')

        register_lock(dump_fd)

        pickle.dump(self._data, dump_fd)

        # flush dump buffer
        dump_fd.flush()

        self._batches.add(dump_fd)

        # dump meta (overwrite the old file)
        self._meta_fd.seek(0)
        self._meta_fd.truncate()
        self._meta_fd.write(ujson.dumps(self._meta).encode('utf-8'))

        # flush meta buffer
        self._meta_fd.flush()

        self._flush()

    def cursor(self):
        """Initialize cursor to the beginning of a collection."""
        return _Cursor(
            data=self._data
        )

    def _encode(self, years: typing.Iterable) -> str:
        """Encode binary mask into hexadecimal format."""
        year_set = set(map(str, years))

        year_range = ['recent', 'modified'] + list(
            range(2001 + self._bitmask_size, 2001, -1)
        )

        mask = [
            ['0', '1'][str(year) in year_set] for year in year_range
        ]

        # return hex mask
        return hex(int("".join(mask), base=2))

    def _decode(self, identifier: str) -> set:
        """Decode hexadecimal string into binary mask."""
        hex_pattern = r"0[xX][0-9a-fA-F]+"

        if not re.match(hex_pattern, identifier):
            raise ValueError("Mask does not match hexadecimal pattern.")

        mask = bin(int(identifier, base=16))[2:].zfill(self._bitmask_size)

        year_range = ['recent', 'modified'] + list(
            map(str, range(2001 + self._bitmask_size, 2001, -1))
        )

        # return set of years
        return set(itertools.compress(year_range, map(int, mask)))

    def _flush(self):
        # overwrite data
        del self._data

        gc.collect()

        self._count = 0
        self._data: typing.List[Document] = [None] * self.STORAGE_BATCH_SIZE


class _Cursor(object):

    def __init__(self,
                 data: typing.Iterable,
                 batch_size: int = 1):
        """Initialize cursor over data."""
        self._data_iterator = iter(data)

        self._batch_size = batch_size

    def next(self):
        batch = None

        try:
            if self._batch_size == 1:
                # batch is a single item
                batch = next(self._data_iterator)

            # accumulate and yield in batches
            else:
                batch = [
                    next(self._data_iterator) for _ in range(self._batch_size)
                ]

        except StopIteration:
            pass

        return batch

    def batch_size(self, batch_size: int):
        self._batch_size = batch_size
