"""Tests for adapters module."""

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

        # ---
        # test dumping multiple batches

        # create new storage for clear env
        tmp_storage = tempfile.mkdtemp(prefix='tests_', suffix='_adapters')

        adapter = DefaultAdapter(storage=tmp_storage, cache_size=2)  # cache every second file
        adapter.connect()
        adapter.process(data=[DOCUMENT] * 10)  # should create 5 batch files + 1 meta file

        self.assertEqual(len(os.listdir(tmp_storage)), 6)

    def test_select(self):
        """Test DefaultAdapters `select` method."""

    def test_project(self):
        """Test DefaultAdapters `project` method."""

    def test_filter(self):
        """Test DefaultAdapters `filter` method."""

    def test_sample(self):
        """Test DefaultAdapters `sample` method."""

    def test_cursor(self):
        """Test DefaultAdapters `cursor` method."""
        tmp_storage = tempfile.mkdtemp(prefix='tests_', suffix='_adapters')

        adapter = DefaultAdapter(storage=tmp_storage)

        adapter.connect()
        adapter.process(data=[DOCUMENT])

        # ---
        # default (single Document), in-memory
        cursor = adapter.cursor()

        self.assertIsInstance(cursor.next(), Document)

        # batch
        cursor = adapter.cursor()

        batch = cursor.next_batch(batch_size=5)

        self.assertIsInstance(batch, list)
        # first entry should be the Document itself
        self.assertTrue(batch[0])
        # rest should be None (preserve consistency)
        self.assertTrue(not any(batch[1:]))
        self.assertEqual(len(batch), 5)

        # ---
        # test cursor over persistent storage files
        # create new storage for clear env
        tmp_storage = tempfile.mkdtemp(prefix='tests_', suffix='_adapters')

        adapter = DefaultAdapter(storage=tmp_storage, cache_size=2)  # cache every second file
        adapter.connect()
        adapter.process(data=[DOCUMENT] * 10)  # should create 5 cache files + 1 meta file

        self.assertEqual(len(os.listdir(tmp_storage)), 6)

        # different initialization
        cursor = adapter.cursor()
        cursor.batch_size(5)

        batch = cursor.next_batch()

        self.assertTrue(all(batch))
        self.assertEqual(len(batch), 5)

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
