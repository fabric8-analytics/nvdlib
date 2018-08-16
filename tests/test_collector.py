"""Tests for collector module."""
import json
import unittest

from nvdlib import model
from nvdlib.collector import Collector


SAMPLE_CVE_PATH = 'data/cve-1.0-sample.json'

with open(SAMPLE_CVE_PATH) as f:
    DATA = json.loads(f.read())


class TestCollection(unittest.TestCase):
    """Test Collector class."""

    def test___init__(self):
        document = model.Document.from_data(DATA)
        collection = Collector([document])

        self.assertIsInstance(collection, Collector)

        # collection should contain 1 document
        self.assertEqual(len(collection), 1)

    def test_select(self):
        pass

    def test_project(self):
        pass

    def test_filter(self):
        pass
