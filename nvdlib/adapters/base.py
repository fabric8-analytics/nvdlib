"""Abstract Base Class for a NVD feed adapter."""
import typing

from abc import ABC, abstractmethod

from nvdlib.selector import Selector


class Document:
    """Forward reference of nvdlib.model.Document class"""


class BaseAdapter(ABC):

    def __init__(self):
        self._count: int = 0
        self._storage: typing.Any = None

        self._data: typing.Any = None

        self._cursor: typing.Any = None

    def __iter__(self):
        self._cursor = self.cursor()
        self._cursor.batch_size(1)

        return self

    def __next__(self):
        return self.next()

    @property
    def storage(self) -> typing.Any:
        return self._storage

    @abstractmethod
    def connect(self, storage: str = None):
        """Connect adapter adapter to a storage."""

    @abstractmethod
    def process(self, data: typing.Iterable["Document"]):
        """Process given data and store in connected storage."""

    @abstractmethod
    def select(self, *selectors: Selector, operator: str = 'AND'):
        """Select documents based on given selector."""

    @abstractmethod
    def project(self, *selectors: Selector):
        """Project specific attributes based on given selectors."""

    @abstractmethod
    def filter(self, fn: callable):
        """Filter documents based on function call."""

    @abstractmethod
    def sample(self, size: int = 20):
        """Draw random sample."""

    @abstractmethod
    def dump(self, storage: typing.Any = None):
        """Dump stored data into a storage."""

    @abstractmethod
    def cursor(self):
        """Initialize cursor to the beginning of a collection.

        The cursor must have implemented at least the following functionality:
            - next() ->
            - batch_size()
        """

    def is_connected(self):
        return self._storage is not None

    def count(self) -> int:
        """Return number of entries in the collection."""
        return self._count

    def next(self):
        """Get next entry from the collection."""
        if self._cursor is None:
            # cursor factory method
            self._cursor = self.cursor()

        self._cursor.batch_size(1)

        return self._cursor.next()

    def next_batch(self, batch_size: int = 20):
        """Get next batch of entries from the collection."""
        if batch_size <= 0:
            raise ValueError(
                f"Argument `batch_size` expected to be > 0"
            )

        if self._cursor is None:
            # cursor factory method
            self._cursor = self.cursor()

        self._cursor.batch_size(batch_size)

        return self._cursor.next()
