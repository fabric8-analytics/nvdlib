"""Tests for nvdlib adapters."""

import os

import json
import tempfile
import unittest

from nvdlib.adapters import DefaultAdapter
from nvdlib.model import Document


SAMPLE_CVE_PATH = 'data/cve-1.0-sample.json'

with open(SAMPLE_CVE_PATH) as f:
    data = json.load(f)

    DOCUMENT: Document = Document.from_data(data)

    del data


class TestDefaultAdapter(unittest.TestCase):

    def test___init__(self):
        """Test DefaultAdapters initialization."""

        adapter = DefaultAdapter()

        self.assertIsInstance(adapter, TestDefaultAdapter)

    def test_connect(self):
        """Test DefaultAdapters `connect` method."""
        tmp_storage = tempfile.mkdtemp(prefix='tests_', suffix='_adapters')

        adapter = DefaultAdapter()
        adapter.connect(storage=tmp_storage)

        self.assertTrue(adapter.storage)

    def test_process(self):
        """Test DefaultAdapters `process` and `cache` methods."""
        tmp_storage = tempfile.mkdtemp(prefix='tests_', suffix='_adapters')

        adapter = DefaultAdapter(storage=tmp_storage)

        adapter.connect()
        adapter.process(data=[DOCUMENT])

        # small sample, dump will not be called
        self.assertTrue(adapter._data)
        self.assertTrue(adapter._meta)
        self.assertIn(DOCUMENT.cve.id_, adapter._meta)

        # meta has been created
        self.assertIn('.meta', os.listdir(tmp_storage))

        # dump has been not created
        self.assertFalse(any([
            not f.startswith('.') for f in os.listdir(tmp_storage)
        ]))

        # ---
        # dump
        adapter.cache()

        # dump has been created
        self.assertEqual(len(os.listdir(tmp_storage)), 2)

        # meta not empty
        with open(os.path.join(tmp_storage, '.meta'), 'r') as f:
            self.assertTrue(f.read())

    def test_select(self):
        """Test DefaultAdapters `select` method."""

    def test_project(self):
        """Test DefaultAdapters `project` method."""

    def test_filter(self):
        """Test DefaultAdapters `filter` method."""

    def test_sample(self):
        """Test DefaultAdapters `sample` method."""

    def test_dump(self):
        """Test DefaultAdapters `dump` method."""

    def test_cursor(self):
        """Test DefaultAdapters `cursor` method."""
        tmp_storage = tempfile.mkdtemp(prefix='tests_', suffix='_adapters')

        adapter = DefaultAdapter(storage=tmp_storage)

        adapter.connect()
        adapter.process(data=[DOCUMENT])

        # default (single Document)
        cursor = adapter.cursor()

        self.assertIsInstance(cursor.next(), Document)

        # batch
        cursor = adapter.cursor()
        cursor.batch_size(5)

        batch = cursor.next()

        print(batch)

        self.assertIsInstance(batch, list)
        # first entry should be the Document itself
        self.assertTrue(batch[0])
        # rest should be None (preserve consistency)
        self.assertTrue(not any([entry for entry in batch[1:]]))
        self.assertEqual(len(batch), 5)

    def test_count(self) -> int:
        """Test DefaultAdapters `count` method."""

    def test_next(self):
        """Test DefaultAdapters `next` method."""

    def test_next_batch(self, batch_size=500):
        """Test DefaultAdapters `next_batch` method."""

    def test__encode(self):
        """Test DefaultAdapters `_encode` method."""
        years = ['2002', '2010', '2018']
        encoded_mask = DefaultAdapter()._encode(years)

        self.assertEqual(encoded_mask, '0x10101')

    def test__decode(self):
        """Test DefaultAdapters `_decode` method."""
        identifier = '0x10101'

        year_set = DefaultAdapter()._decode(identifier)

        # sanity check
        self.assertIsInstance(year_set, set)
        self.assertEqual(len(year_set), 3)

        # exact check
        self.assertEqual(year_set, {2002, 2010, 2018})
