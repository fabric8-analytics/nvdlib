"""Module defining Collector class -- a facade for handling document operations using adapters."""

import os
import shutil
import tempfile

import typing
import textwrap

from nvdlib import adapters
from nvdlib.model import Document


class Collection(object):
    """Facade to handle storage operations and collections of Documents."""

    def __init__(self,
                 data_iterator: typing.Iterable[Document],
                 storage: str = None,
                 adapter: str = 'DEFAULT'
                 ):
        self._name: str = None

        self._count: int = 0
        self._clear_storage = True  # in the future, this argument can be modifiable

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
           _id: {_id}
           name: '{name}'
           adapter: '{adapter}',
           documents: {count}
        }}
        """).format(_id=id(self),
                    name=self.name,
                    adapter=self._adapter.name,
                    count=self._count)

        return collection_repr

    @property
    def storage(self):
        return self._storage

    def count(self) -> int:
        """Return number of documents in the collection."""
        return self._adapter.count()

    def find(self,
             selector: typing.Dict[str, typing.Any] = None,
             limit: int = None) -> "Collection":
        """Find documents based on given selector."""

        if not selector:
            return self

        collection: Collection = Collection(self._adapter.find(
            selectors=selector,
            limit=limit
        ))

        return collection

    def cursor(self):
        return self._adapter.cursor()

    def sample(self, sample_size: int = 20):
        return self._adapter.sample(sample_size)

    def pretty(self, sample_size: int = 20):
        for doc in self._adapter.sample(sample_size):
            doc.pretty()
