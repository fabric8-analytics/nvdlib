"""Default adapter."""

import atexit
import fcntl
import gc
import io
import os
import re

import datetime
import time

import itertools
import random
import typing

import pickle
import ujson

from collections import OrderedDict

from nvdlib.adapters.base import BaseAdapter, BaseCursor
from nvdlib.model import Document
from nvdlib import query_selectors


__LOCKS = set()

_CVE_ID_PATTERN = r"CVE-(20[0-9]{2})-([0-9]+)"
_DUMP_PATTERN = r"(?<identifier>\d+)(?<hexmask>0[xX][0-9a-fA-F]+)(?<size>[0-9]+)(?<timestamp>(\d+).(\d+))"


def register_lock(*fd):
    """Register and lock given file descriptors."""
    global __LOCKS

    tolock_fd: io.BytesIO
    for tolock_fd in fd:
        if tolock_fd is None:  # this can happen with default initialization of an adapter
            continue

        fcntl.flock(tolock_fd, fcntl.LOCK_EX | fcntl.LOCK_NB)

        # add lock to global handle
        __LOCKS.add(fd)


def release_lock(*fd):
    """Release locks on given file descriptors and close them."""
    global __LOCKS

    locked_fd: io.BytesIO
    for locked_fd in fd:
        if locked_fd is None:  # this can happen with default initialization of an adapter
            continue

        fcntl.flock(locked_fd, fcntl.LOCK_UN)
        # wait for lock to be released
        time.sleep(0.1)

        if not locked_fd.closed:
            # flush the buffer and close the descriptor
            locked_fd.close()

        try:
            # remove lock from global handle
            __LOCKS.remove(fd)
        except KeyError:
            pass


atexit.register(release_lock, *__LOCKS)


class DefaultAdapter(BaseAdapter):
    """Default storage adapter."""

    __SHARD_SIZE = 5000
    __BITMASK_SIZE = 32

    def __init__(self, storage: str = None, shard_size: int = None):
        """Initialize DefaultAdapter instance."""
        # run this before any other initialization
        super(DefaultAdapter, self).__init__(name='DEFAULT')

        self._count = 0

        self._storage = storage
        self._shard_size = shard_size or self.__SHARD_SIZE

        self._data: typing.List[Document] = [None] * self._shard_size

        self._meta: typing.Dict[str, dict] = {
            'cve_data': OrderedDict(),
            'shard_data': OrderedDict()
        }
        self._cve_meta = self._meta['cve_data']
        self._shard_meta = self._meta['shard_data']

        self._meta_fpath = None
        self._meta_fd = None
        self._shards = list()  # set of file descriptors

        self._schema: dict = None

    def __del__(self):
        """Finalize object destruction."""
        release_lock(*self._shards, self._meta_fd)

    @property
    def shard_size(self):
        return self._shard_size

    def set_shard_size(self, size: int):
        """Resize storage shard size.

        NOTE: This is an expansive operation as all recorded data has to be processed again
        to match the new storage size.
        It is recommended to provide desired cache size during initialization.
        """
        if size == self._shard_size:
            return

        raise NotImplementedError("This functionality has not been implemented yet. Please use recommended approach"
                                  " and provide `cache_size` during initialization of `DefaultAdapter`.")

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
        self._meta = ujson.loads(self._meta_fd.read().decode('utf-8') or '{}') or self._meta

        self._cve_meta = self._meta['cve_data']
        self._shard_meta = self._meta['shard_data']

        for value_dict in self._cve_meta.values():

            batch_file = value_dict['batch']
            batch_fpath = os.path.join(self._storage, batch_file)
            batch_fd = open(batch_fpath, 'r+b')

            register_lock(batch_fd)

            self._shards.append(batch_fd)

        return self

    def process(self, data: typing.Iterable["Document"]):
        """Process given data and store in connected storage."""

        index = 0
        count = 0

        for document in data:
            # noinspection PyUnresolvedReferences
            assert document.cve, f"Invalid document: {document}"
            # noinspection PyUnresolvedReferences
            document_id: str = document.cve.id_

            # store meta pointer to current batch and position
            self._cve_meta[document_id] = {'index': index, 'shard': None}
            self._data[index] = document

            count += 1

            index = count % self._shard_size
            if index == 0:
                self.dump_shard()

        self._count = count

        return self

    def count(self) -> int:
        """Return number of documents in the collection."""
        return self._count

    # TODO: limit number of yielded documents
    def find(self,
             selectors: typing.Dict[str, typing.Any] = None,
             limit: int = None) -> typing.Iterator[Document]:
        """Find documents based on given selectors."""
        if any(self._data):  # for consistency, dump all the data into shards
            self.dump_shard()

        if limit is not None:
            if limit <= 0 or not isinstance(limit, int):
                raise ValueError(f"`limit` must be integer greater than 0, got: {limit}")

        # release locks and close descriptors (pass ownership to threads)
        # release_lock(*self._shards, self._meta_fd)

        # TODO create model schema as AttrDict to check key validity
        # schema = ModelSchema()

        # for key, value in selectors.items():
        #     if not utils.rhasattr(schema, key):
        #         raise ValueError(f"Invalid key: {key}")

        for shard in self._shards:
            yield from self.__find(selectors, shard)

    # noinspection PyMethodMayBeStatic
    def __find(self, selectors: dict, shard: io.BytesIO):

        shard.seek(0)
        data = pickle.load(shard)

        entry: Document
        for entry in data:
            discard = False
            for attr, pattern in selectors.items():
                if not isinstance(pattern, typing.Callable):
                    select: typing.Callable = query_selectors.match(pattern)
                else:
                    select: typing.Callable = pattern

                if not select(entry, attr):
                    discard = True
                    break

            if not discard:
                yield entry

    def dump(self, storage: typing.Any = None):
        """Dump stored data into a storage."""
        raise NotImplementedError

    def dump_shard(self, flush=True):
        """Store data as shards."""
        shard_number = len(self._shards)

        year_pattern = r"(?:CVE-)(\d+)(?:-\d+)"

        timestamp = int(datetime.datetime.now().timestamp())

        years_in_batch = set(map(
            lambda cve_id: re.findall(year_pattern, cve_id)[0],
            self._cve_meta.keys()
        ))

        shard_data = [item for item in self._data if item]

        # construct file name
        encoded_bitmask = self._encode(years_in_batch)
        shard_file = f"{shard_number}.{encoded_bitmask}.{len(shard_data)}.{timestamp}"

        dump_path = os.path.join(self._storage, shard_file)

        for key in self._cve_meta.keys():
            self._cve_meta[key].update({'shard': shard_number})

        # dump batch
        shard = open(dump_path, 'a+b')
        register_lock(shard)
        pickle.dump(shard_data, shard)

        # flush dump buffer
        shard.flush()

        self._shards.append(shard)

        self._shard_meta[shard_number] = OrderedDict(
            id=shard_number,
            mask=encoded_bitmask,
            size=len(shard_data),
            timestamp=timestamp
        )

        # dump meta (overwrite the old file)
        self._meta_fd.seek(0)
        self._meta_fd.truncate()
        self._meta_fd.write(ujson.dumps(self._meta).encode('utf-8'))

        # flush meta buffer
        self._meta_fd.flush()

        if flush:
            self._flush()

    def cursor(self):
        """Initialize cursor to the beginning of a collection."""
        if self._shards:
            cursor = Cursor(
                shards=self._shards
            )
        else:
            cursor = Cursor(
                data=[
                    item for item in self._data if item is not None
                ]
            )

        return cursor

    def sample(self, sample_size: int = 20, entire=False):
        """Draw random sample.

        If `entire` is set to True (default: False), draws the sample from stored
        data otherwise only from buffer.

        NOTE: In case there is a need for more accurate representation of stored data,
        it is recommended to use `entire=True`, otherwise due to its significant performance
        overhead, default value (False) is recommended.
        """
        sample_size = int(sample_size)

        if sample_size <= 0:
            raise ValueError("`sample_size` must be >= 0")

        buffer_size = 0
        for item in self._data:
            buffer_size += int(item is not None)

        if buffer_size >= sample_size and not entire:
            # use default method in case enough data are present in the buffer
            sample = super(DefaultAdapter, self).sample(sample_size=sample_size)

        else:  # use all shards in order to get more accurate distribution

            # check if there is enough data
            total_data = sum([
                shard['size'] for shard in self._shard_meta.values()
            ])

            if total_data < sample_size:
                raise ValueError("`sample_size` can not be greater than the total amount of data.")

            num_shards = len(self._shards)
            avg = sample_size // min(num_shards, sample_size)
            samples_per_shard = [0] * num_shards

            # evenly distribute
            distributed = 0
            while distributed < sample_size:
                for i, shard in enumerate(self._shard_meta.values()):
                    shard_size = shard['size']
                    shard_sample = avg if avg <= shard_size else shard_size

                    distributed += shard_sample
                    samples_per_shard[i] = shard_sample

                    if distributed >= sample_size:
                        break

            sample = [None] * sample_size

            for i, shard in enumerate(self._shards):
                shard_sample_size = samples_per_shard[i]

                if not shard_sample_size:
                    continue

                shard.seek(0)
                shard_data = pickle.load(shard, encoding='utf-8')

                sample[i:(i + shard_sample_size)] = random.choices(
                    shard_data, k=shard_sample_size
                )

        return sample

    def _encode(self, years: typing.Iterable) -> str:
        """Encode binary mask into hexadecimal format."""
        year_set = set(map(str, years))

        year_range = ['recent', 'modified'] + list(
            range(2001 + self.__BITMASK_SIZE, 2001, -1)
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

        mask = bin(int(identifier, base=16))[2:].zfill(self.__BITMASK_SIZE)

        year_range = ['recent', 'modified'] + list(
            map(str, range(2001 + self.__BITMASK_SIZE, 2001, -1))
        )

        # return set of years
        return set(itertools.compress(year_range, map(int, mask)))

    def _flush(self):
        # overwrite data
        del self._data

        gc.collect()

        self._count = 0
        self._data: typing.List[Document] = [None] * self._shard_size


class Cursor(BaseCursor):
    """One-shot iterator over data storage."""

    def __init__(self,
                 data: typing.Iterable = None,
                 shards: typing.Iterable[io.BytesIO] = None,
                 batch_size: int = 20):
        """Initialize iterator over data or batch files (only one needs to be specified)."""
        if not any([data, shards]):
            raise ValueError("Either in-memory data or persistent storage files must be provided.")

        if all([data, shards]):
            raise ValueError("Cursor can not iterate over both in-memory data and persistent storage.")

        self._index = 0
        self._data = data

        self._count = 0

        self._shards = shards
        self._batch_size = batch_size

        # initialize iterator
        self._data_iterator = self.get_iterator()

    @property
    def index(self):
        return self._index

    def next(self) -> Document:
        """Return next element."""
        ret = next(self._data_iterator)
        self._index += 1

        return ret

    def next_batch(self, batch_size: int = None) -> typing.Sized:
        """Return next batch of elements."""
        # accumulate and yield in batches
        if batch_size is None or batch_size <= 0:
            batch_size = self._batch_size

        batch = [None] * batch_size
        for i in range(batch_size):
            try:
                batch[i] = next(self._data_iterator)
                self._index += 1
            except StopIteration:
                break

        return batch

    def batch_size(self, batch_size: int):
        """Set batch size."""
        self._batch_size = batch_size

    def get_iterator(self) -> typing.Iterator:
        """Iterate over stored data."""

        if self._data:
            yield from iter(self._data)

        else:
            for shard in self._shards:
                shard.seek(0)
                data = pickle.load(shard, encoding='utf-8')
                yield from iter(data)
