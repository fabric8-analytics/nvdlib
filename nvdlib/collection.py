"""Module defining Collector class -- a facade for handling document operations using adapters."""

import os
import shutil
import tempfile

import typing
import textwrap

from nvdlib import adapters
from nvdlib.model import Document
from nvdlib.selector import Selector


class Collection(object):
    """Facade to handle storage operations and collections of Documents."""

    def __init__(self,
                 data_iterator: typing.Iterable[Document],
                 storage: str = None,
                 adapter: str = 'DEFAULT'
                 ):
        self._name: str = None

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

    @property
    def name(self):
        return self._name

    def set_name(self, name: str):
        self._name = name

    def __del__(self):
        """Finalize object destruction."""
        if self._clear_storage:
            shutil.rmtree(self._storage)

    def __len__(self):
        """Returns number of documents stored in this collection."""
        return self._count

    def __repr__(self):
        """Returns unique representation of collection."""
        collection_repr = textwrap.dedent("""
        Collection: {{
           id: {id}
           name: '{name}'
           adapter: '{adapter}',
           documents: {count}
        }}
        """).format(id=id(self),
                    name=self.name,
                    adapter=self._adapter.name,
                    count=self._count)

        return collection_repr

    @property
    def storage(self):
        return self._storage

    def count(self):
        return self._adapter.count()

    def select(self, *selectors: Selector, operator='AND') -> "Collection":
        collection = self._adapter.select(*selectors, operator=operator)

        return collection

    def project(self, *selectors: Selector):
        raise NotImplementedError

    def filter(self, fn: callable):
        raise NotImplementedError

    def cursor(self):
        return self._adapter.cursor()
