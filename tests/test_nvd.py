import datetime
import os
import psutil
import tempfile
import unittest

from nvdlib.nvd import NVD, JSONFeed, JSONFeedMetadata


_TEMP_DATA_DIR = tempfile.mkdtemp(prefix='tests_', suffix='_nvd')


class TestJSONFeedMetadata(unittest.TestCase):
    """Tests for TestJSONFeedMetadata class."""

    def test___init__(self):
        """Test JSONFeedMetadata initialization."""
        meta_temp_dir = tempfile.mkdtemp(dir=_TEMP_DATA_DIR)

        # existing, update=False
        feed_name = 'sample'
        meta = JSONFeedMetadata(feed_name=feed_name, data_dir=meta_temp_dir)

        # meta object created
        self.assertIsInstance(meta, JSONFeedMetadata)

        # non-existing, update=False
        feed_name = 'modified'
        meta = JSONFeedMetadata(feed_name=feed_name, data_dir=meta_temp_dir)

        # meta object created
        self.assertIsNotNone(meta)
        # should not be ready
        self.assertFalse(meta.is_downloaded())
        self.assertFalse(meta.is_parsed())
        self.assertFalse(meta.is_ready())

        # non-existing, update=True
        meta = JSONFeedMetadata(
            feed_name=feed_name,
            data_dir=meta_temp_dir,
            update=True
        )

        # should be ready
        self.assertTrue(meta.is_ready())

        # file should exist
        self.assertTrue(os.path.exists(meta.path))

        # file content should not be empty
        with open(meta.path, 'r') as f:
            self.assertTrue(f.readline())

    def test__parse_metadata(self):
        """Test JSONFeedMetadata `_parse_metadata` method."""
        meta_file = 'data/nvdcve-1.0-sample.meta'
        with open(meta_file, 'r') as f:
            meta_data = f.read()

        parsed = JSONFeedMetadata.parse_metadata(meta_data)

        # not empty
        self.assertTrue(parsed)

        # is dict
        self.assertIsInstance(parsed, dict)

        metadata_dict_template = {
            'last_modified': datetime.datetime,
            'size': int,
            'zipSize': int,
            'gzSize': int,
            'sha256': str
        }

        for key, type_ in metadata_dict_template.items():
            parsed_value = parsed[key]

            # correct type
            self.assertIsInstance(parsed_value, type_)

            # not empty
            self.assertTrue(parsed_value)

    def test_fetch(self):
        """Test TestJSONFeedMetadata `fetch` method."""
        feed_name = 'modified'
        meta_temp_dir = tempfile.mkdtemp(dir=_TEMP_DATA_DIR)

        meta = JSONFeedMetadata(feed_name=feed_name,
                                data_dir=meta_temp_dir)

        metadata: str = meta.fetch().data

        self.assertIsInstance(metadata, str)
        self.assertTrue(metadata)

    def test_update(self):
        """Test TestJSONFeedMetadata `update` method."""
        feed_name = 'modified'
        meta_temp_dir = tempfile.mkdtemp(dir=_TEMP_DATA_DIR)

        meta = JSONFeedMetadata(feed_name=feed_name,
                                data_dir=meta_temp_dir)

        metadata: str = meta.fetch().data

        self.assertIsInstance(metadata, str)
        self.assertTrue(metadata)

        # should not be ready
        self.assertFalse(meta.is_ready())

        meta.update()

        # should be ready now
        self.assertTrue(meta.is_ready())

        # metadata present in the directory
        self.assertTrue(meta.filename in os.listdir(meta_temp_dir))


class TestJSONFeed(unittest.TestCase):
    """Tests for JSONFeed class."""

    def test_init(self):
        """Test JSONFeed initialization."""
        feed_name = 'sample'
        json_dir = tempfile.mkdtemp(dir=_TEMP_DATA_DIR)

        # non-existing
        json_feed = JSONFeed(feed_name, data_dir=json_dir)

        # correct object created
        self.assertIsInstance(json_feed, JSONFeed)
        # non empty
        self.assertTrue(json_feed)

        # existing
        json_feed = JSONFeed(feed_name, data_dir='data/')

        # correct object created
        self.assertIsInstance(json_feed, JSONFeed)
        # non empty
        self.assertTrue(json_feed)

    def test_download(self):
        """Test JSONFeed `download` method."""
        feed_name = 'modified'
        json_dir = tempfile.mkdtemp(dir=_TEMP_DATA_DIR)

        # feed does not exist yet
        json_feed = JSONFeed(feed_name, data_dir=json_dir)

        self.assertIsInstance(json_feed, JSONFeed)
        # nothing has been downloaded yet
        self.assertTrue(not os.listdir(json_dir))
        # feed is not ready
        self.assertFalse(json_feed.is_ready())

        json_feed.download()

        self.assertTrue(json_feed.filename in os.listdir(json_dir))
        self.assertTrue(json_feed.is_downloaded())
        # feed should not contain any data atm
        self.assertIsNone(json_feed.data)

        # load the data
        json_feed.load()

        # should be json dict
        self.assertIsInstance(json_feed.data, dict)

    def test_load(self):
        """Test JSONFeed `load` methods."""
        # test factory load
        feed_name = 'sample'
        json_feed = JSONFeed.load(feed_name, data_dir='data/')

        self.assertIsInstance(json_feed, JSONFeed)
        self.assertIsInstance(json_feed.data, dict)

        # test download-load
        feed_name = 'modified'
        json_feed = JSONFeed(feed_name, load=True, data_dir='data/')

        self.assertIsInstance(json_feed, JSONFeed)
        self.assertIsInstance(json_feed.data, dict)

    def test_flush(self):
        """Test JSONFeed `flush` method."""
        feed_name = 'sample'
        json_feed = JSONFeed.load(feed_name, data_dir='data/')

        # feed should not contain any data atm
        self.assertTrue(json_feed.data)

        process = psutil.Process()
        memory_usage = process.memory_info().rss

        # flush the data
        json_feed.flush()

        self.assertIsNone(json_feed.data)

        # sanity check -- lower memory usage
        self.assertLessEqual(process.memory_info().rss, memory_usage)


class TestNVD(unittest.TestCase):
    """Tests for NVD class."""

    def test___init__(self):
        """Test NVD initialization."""

    def test_update(self):
        pass
