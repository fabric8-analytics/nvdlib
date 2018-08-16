"""Module defining Collector class -- a facade for handling document operations using adapters."""

import os
import shutil
import tempfile

import typing

from nvdlib import adapters
from nvdlib.model import Document
from nvdlib.selector import Selector


class Collector(object):
    """Facade to handle storage operations and collections of Documents."""

    def __init__(self,
                 data_iterator: typing.Iterable[Document],
                 storage: str = None,
                 adapter: str = 'DEFAULT'
                 ):
        self._count: int = 0
        self._clear_storage = True

        if storage:
            self._clear_storage = False
            self._storage = storage

        else:
            self._storage = storage or os.path.join(
                tempfile.gettempdir(),
                f"nvdlib/.dump/{id(self)}"
            )

        # create directory
        os.makedirs(self._storage)

        # initialize adapter
        self._adapter: adapters.BaseAdapter = getattr(
            adapters,  # load adapter directly from module
            adapter.upper()
        )()

        self._adapter.connect(storage=self._storage)
        self._adapter.process(data_iterator)

        self._data = self._adapter.sample()
        self._count = self._adapter.count()

    def __del__(self):
        if self._clear_storage:
            shutil.rmtree(self._storage)

    def __len__(self):
        return self._count

    @property
    def storage(self):
        return self._storage

    def count(self):
        return self._adapter.count()

    def select(self, *selectors: Selector, operator='AND'):
        self._adapter.select(*selectors, operator=operator)

        return self

    def project(self, *selectors: Selector):
        raise NotImplementedError

    def filter(self, fn: callable):
        raise NotImplementedError

    def cursor(self):
        return self._adapter.cursor()
