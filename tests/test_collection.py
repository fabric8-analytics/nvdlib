"""Tests for collector module."""
import json
import unittest

from nvdlib import model
from nvdlib.collection import Collection
from nvdlib.manager import FeedManager


SAMPLE_CVE_PATH = 'data/cve-1.0-sample.json'

with open(SAMPLE_CVE_PATH) as f:
    DATA = json.loads(f.read())


class TestCollection(unittest.TestCase):
    """Test Collection class."""

    def test___init__(self):
        document = model.Document.from_data(DATA)
        collection = Collection([document])

        self.assertIsInstance(collection, Collection)
        self.assertEqual(collection.count(), 1)

        # collection should contain 1 document
        self.assertEqual(len(collection), 1)

    def test_cursor(self):
        document = model.Document.from_data(DATA)
        collection = Collection([document])

        cursor = collection.cursor()

        doc = cursor.next()

        self.assertIsInstance(doc, model.Document)
        self.assertEqual(doc, document)

        # in this case (non-caching mode), collection should also preserve reference to the doc
        self.assertEqual(id(doc), id(document))
