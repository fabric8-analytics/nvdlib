"""Tests for adapters module."""

import os
import json
import tempfile
import unittest
from pathlib import Path

from nvdlib.adapters import DefaultAdapter
from nvdlib.model import Document

import nvdlib.query_selectors as selectors


SAMPLE_CVE_PATH = Path(__file__).parent / 'data/cve-1.0-sample.json'

with open(SAMPLE_CVE_PATH) as f:
    data = json.load(f)

    DOCUMENT: Document = Document.from_data(data)

    del data


class TestDefaultAdapter(unittest.TestCase):

    def test___init__(self):
        """Test DefaultAdapters initialization."""

        adapter = DefaultAdapter()

        self.assertIsInstance(adapter, DefaultAdapter)

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
        self.assertIn(DOCUMENT.cve.id_, adapter._cve_meta)

        # meta has been created
        self.assertIn('.meta', os.listdir(tmp_storage))

        # dump has been not created
        self.assertFalse(any([
            not f.startswith('.') for f in os.listdir(tmp_storage)
        ]))

        # ---
        # dump shard
        adapter.dump_shard()

        # dump has been created
        self.assertEqual(len(os.listdir(tmp_storage)), 2)

        # meta not empty
        with open(Path(tmp_storage) / '.meta', 'r') as f:
            self.assertTrue(f.read())

        # ---
        # test dumping multiple shards

        # create new storage for clear env
        tmp_storage = tempfile.mkdtemp(prefix='tests_', suffix='_adapters')

        adapter = DefaultAdapter(storage=tmp_storage, shard_size=2)  # cache every other entry
        adapter.connect()
        adapter.process(data=[DOCUMENT] * 10)  # should create 5 shards + 1 meta file

        self.assertEqual(len(os.listdir(tmp_storage)), 6)

    def test_find(self):
        """Test DefaultAdapters `find` method."""
        tmp_storage = tempfile.mkdtemp(prefix='tests_', suffix='_adapters')

        adapter = DefaultAdapter(storage=tmp_storage)

        adapter.connect()
        adapter.process(data=[DOCUMENT] * 10)

        # invalid key
        # with self.assertRaises(ValueError):
        #     _ = list(adapter.find({'wrong-key': 'non-existing'}))

        # not finding anything
        collection = list(adapter.find({'cve.id_': 'non-existing'}))
        self.assertEqual(len(collection), 0)

        # find specific id
        collection = list(adapter.find({'cve.id_': 'CVE-2015-0001'}))
        self.assertEqual(len(collection), 10)

        # multiple selectors
        collection = list(adapter.find({'cve.id_': 'CVE-2015-0001',
                                        'impact.impact_score': 2.9}))
        self.assertEqual(len(collection), 10)

        # special selector
        collection = list(adapter.find({'cve.id_': selectors.match('CVE-2015-0001')}))
        self.assertEqual(len(collection), 10)

        # ---
        # array access
        collection = list(adapter.find({
            'cve.affects.data.vendor_name': 'microsoft'
        }))
        self.assertEqual(len(collection), 10)

        # array access
        collection = list(adapter.find({
            'cve.affects.data.product_name': selectors.match('windows')
        }))
        self.assertEqual(len(collection), 0)

        collection = list(adapter.find({
            'cve.affects.data.product_name': selectors.search('windows')
        }))
        self.assertEqual(len(collection), 10)

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

        adapter = DefaultAdapter(storage=tmp_storage, shard_size=2)  # dump every other entry
        adapter.connect()
        adapter.process(data=[DOCUMENT] * 10)  # should create 5 shards + 1 meta file

        self.assertEqual(len(os.listdir(tmp_storage)), 6)

        # different initialization
        cursor = adapter.cursor()
        cursor.batch_size(5)

        batch = cursor.next_batch()

        self.assertTrue(all(batch))
        self.assertEqual(len(batch), 5)

    def test_sample(self):
        """Test DefaultAdapters `sample` method."""
        tmp_storage = tempfile.mkdtemp(prefix='tests_', suffix='_adapters')

        adapter = DefaultAdapter(storage=tmp_storage, shard_size=2)  # dump every other entry
        adapter.connect()
        adapter.process(data=[DOCUMENT] * 15)  # should create 5 shards + 1 meta file

        # small sample size -- draw from buffer
        self.assertGreater(len(adapter._data), 0)

        sample = adapter.sample(sample_size=1)
        self.assertEqual(len(sample), 1)
        self.assertIsInstance(sample[0], Document)

        # ---
        # bigger sample size
        sample = adapter.sample(sample_size=5)
        self.assertEqual(len(sample), 5)
        self.assertTrue(all([isinstance(s, Document) for s in sample]))

        # ---
        # too big
        with self.assertRaises(ValueError):
            _ = adapter.sample(sample_size=20)

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
        self.assertEqual(year_set, {'2004', '2012', '2020'})
