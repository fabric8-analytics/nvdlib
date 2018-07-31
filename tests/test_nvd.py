import datetime
import os
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
        feed_name = 'recent'
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
        feed_name = 'recent'
        meta_temp_dir = tempfile.mkdtemp(dir=_TEMP_DATA_DIR)

        meta = JSONFeedMetadata(feed_name=feed_name,
                                data_dir=meta_temp_dir)

        metadata: str = meta.fetch()

        self.assertIsInstance(metadata, str)
        self.assertTrue(metadata)

    def test_update(self):
        """Test TestJSONFeedMetadata `update` method."""
        feed_name = 'recent'
        meta_temp_dir = tempfile.mkdtemp(dir=_TEMP_DATA_DIR)

        meta = JSONFeedMetadata(feed_name=feed_name,
                                data_dir=meta_temp_dir)

        metadata: str = meta.fetch()

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

    def test_fetch(self):
        """Test JSONFeed `download` method."""
        pass

    def test_write(self):
        pass

    def test_is_downloaded(self):
        pass

    def test_flush(self):
        pass


class TestNVD(unittest.TestCase):
    """Tests for NVD class."""

    def test___init__(self):
        """Test NVD initialization."""

    def test_update(self):
        pass

