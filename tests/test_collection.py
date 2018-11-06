"""Tests for collector module."""
import os
import json
import typing
import unittest

from nvdlib import model, utils
from nvdlib.collection import Collection


SAMPLE_CVE_PATH = SAMPLE_CVE_PATH = os.path.join(os.path.dirname(__file__), 'data/cve-1.0-sample.json')

with open(SAMPLE_CVE_PATH) as f:
    DATA = json.loads(f.read())


class TestCollection(unittest.TestCase):
    """Test Collection class."""

    def test___init__(self):
        """Test Collection `__init__` method."""
        document = model.Document.from_data(DATA)
        collection = Collection([document])

        self.assertIsInstance(collection, Collection)
        self.assertEqual(collection.count(), 1)

        # collection should contain 1 document
        self.assertEqual(len(collection), 1)

    def test_cursor(self):
        """Test Collection `cursor` method."""
        document = model.Document.from_data(DATA)
        collection = Collection([document])

        cursor = collection.cursor()

        doc = cursor.next()

        self.assertIsInstance(doc, model.Document)
        self.assertEqual(doc, document)

        # in this case (non-caching mode), collection should also preserve reference to the doc
        self.assertEqual(id(doc), id(document))

    def test_project(self):
        """Test Collection `project` method."""
        document = model.Document.from_data(DATA)
        collection = Collection([document])

        it = collection.project({'cve.id_': 1})

        self.assertIsInstance(it, typing.Iterator)

        projection, = list(it)

        self.assertIsInstance(projection, utils.AttrDict)
        self.assertEqual(len(projection.keys()), 2)
        self.assertTrue(projection['id_'])
        self.assertTrue(projection['cve'].id_)

        it = collection.project({'id_': 0, 'cve.id_': 1})
        projection, = list(it)

        self.assertIsInstance(projection, utils.AttrDict)
        self.assertEqual(len(projection.keys()), 1)

        with self.assertRaises(AttributeError):
            self.assertTrue(projection['id_'])

        self.assertTrue(projection['cve'].id_)

    def test_pretty(self):
        """Test Collection `pretty` method."""
        document = model.Document.from_data(DATA)
        collection = Collection([document])

        # should not raise
        collection.pretty()  # default sample size: 20
