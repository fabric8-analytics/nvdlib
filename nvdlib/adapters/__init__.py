"""Adapters to handle backend NVD data operations."""

from nvdlib.adapters.base import BaseAdapter
from nvdlib.adapters.default import DefaultAdapter

__all__ = ['BaseAdapter', 'DefaultAdapter']


DEFAULT = DefaultAdapter
