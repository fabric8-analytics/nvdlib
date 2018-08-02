import asyncio
import datetime
import os
import psutil
import tempfile
import unittest

from nvdlib.nvd import JSONFeedManager, JSONFeed, JSONFeedMetadata


_EVENT_LOOP = asyncio.get_event_loop()
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
        # existing
        feed_name = 'sample'
        meta = JSONFeedMetadata(feed_name=feed_name,
                                data_dir='data')

        future = asyncio.ensure_future(meta.fetch())
        metadata: JSONFeedMetadata = _EVENT_LOOP.run_until_complete(future)
        data: str = metadata.data

        self.assertIsInstance(data, str)
        self.assertTrue(data)

        feed_name = 'modified'
        meta_temp_dir = tempfile.mkdtemp(dir=_TEMP_DATA_DIR)

        # non-existing metadata
        meta = JSONFeedMetadata(feed_name=feed_name,
                                data_dir=meta_temp_dir)

        future = asyncio.ensure_future(meta.fetch())
        metadata: JSONFeedMetadata = _EVENT_LOOP.run_until_complete(future)
        data: str = metadata.data

        self.assertIsInstance(data, str)
        self.assertTrue(data)

    def test_update(self):
        """Test TestJSONFeedMetadata `update` method."""
        feed_name = 'modified'
        meta_temp_dir = tempfile.mkdtemp(dir=_TEMP_DATA_DIR)

        meta = JSONFeedMetadata(feed_name=feed_name,
                                data_dir=meta_temp_dir)

        future = asyncio.ensure_future(meta.fetch())
        metadata: JSONFeedMetadata = _EVENT_LOOP.run_until_complete(future)
        data: str = metadata.data

        self.assertIsInstance(data, str)
        self.assertTrue(data)

        # should not be ready
        self.assertFalse(meta.is_ready())

        _EVENT_LOOP.run_until_complete(meta.update())

        # should be ready now
        self.assertTrue(meta.is_ready())

        # metadata present in the directory
        self.assertTrue(meta.filename in os.listdir(meta_temp_dir))

    def test_url_exists(self):
        """Test TestJSONFeedMetadata `url_exists` method."""
        # existing
        feeds = ['recent', 2018]

        # asynchronous method!
        futures = [
            asyncio.ensure_future(JSONFeedMetadata.url_exists(feed))
            for feed in feeds
        ]
        results = asyncio.gather(*futures)
        results = _EVENT_LOOP.run_until_complete(results)

        self.assertTrue(all([r is True for r in results]))

        # non-existing
        feeds = ['nope', 'non-existing', 0, 1E+5]

        futures = [
            asyncio.ensure_future(JSONFeedMetadata.url_exists(feed))
            for feed in feeds
        ]
        results = asyncio.gather(*futures)
        results = _EVENT_LOOP.run_until_complete(results)

        self.assertTrue(all([r is False for r in results]))

    def test_metadata_exist(self):
        """Test TestJSONFeedMetadata `metadata_exist` method."""
        # existing
        feeds = ['sample']

        futures = [
            asyncio.ensure_future(
                JSONFeedMetadata.metadata_exist(feed, data_dir='data/')
            )
            for feed in feeds
        ]
        results = asyncio.gather(*futures)
        results = _EVENT_LOOP.run_until_complete(results)

        self.assertTrue(all([r is True for r in results]))

        # non-existing
        feeds = ['nope', 'non-existing', 0, 1E+5]

        futures = [
            asyncio.ensure_future(JSONFeedMetadata.metadata_exist(feed))
            for feed in feeds
        ]
        results = asyncio.gather(*futures)
        results = _EVENT_LOOP.run_until_complete(results)

        self.assertTrue(all([r is False for r in results]))


class TestJSONFeed(unittest.TestCase):
    """Tests for JSONFeed class."""

    def test___init__(self):
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

        _EVENT_LOOP.run_until_complete(json_feed.download())

        self.assertTrue(json_feed.filename in os.listdir(json_dir))
        self.assertTrue(json_feed.is_downloaded())
        # feed should not contain any data atm
        self.assertIsNone(json_feed.data)

        # load the data
        _EVENT_LOOP.run_until_complete(json_feed.load())

        # should be json dict
        self.assertIsInstance(json_feed.data, dict)

        # ---
        # test factory download

        feed_name = 'modified'
        json_dir = tempfile.mkdtemp(dir=_TEMP_DATA_DIR)
        json_feed = JSONFeed.download(
            feed_name, data_dir=json_dir, load=True
        )

        self.assertIsInstance(json_feed, JSONFeed)
        self.assertIsInstance(json_feed.data, dict)

        # load the data
        _EVENT_LOOP.run_until_complete(json_feed.load())

        # should be json dict
        self.assertIsInstance(json_feed.data, dict)

    def test_load(self):
        """Test JSONFeed `load` methods."""
        # test factory load

        feed_name = 'sample'
        json_feed = JSONFeed.load(feed_name, data_dir='data/')

        self.assertIsInstance(json_feed, JSONFeed)
        self.assertIsInstance(json_feed.data, dict)

        # ---
        # test async load

        json_feed = JSONFeed.load(feed_name, data_dir='data/')

        self.assertIsInstance(json_feed, JSONFeed)
        self.assertIsInstance(json_feed.data, dict)

        # ---
        # test download-load

        feed_name = 'modified'
        json_feed = JSONFeed(feed_name, data_dir='data/')

        _EVENT_LOOP.run_until_complete(
            json_feed.download(load=True)
        )

        json_feed = JSONFeed.load(feed_name, data_dir='data/')

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


class TestJSONFeedManager(unittest.TestCase):
    """Tests for JSONFeedManager class."""

    def test___init__(self):
        """Test JSONFeedManager initialization."""
        # default
        feed_manager = JSONFeedManager()
        self.assertIsInstance(feed_manager, JSONFeedManager)

        # existing feeds, remote
        feed_manager = JSONFeedManager(['recent', 'modified', 2002])
        self.assertIsInstance(feed_manager, JSONFeedManager)

        # existing feeds, local
        feed_manager = JSONFeedManager(['sample'], data_dir='data/')
        self.assertIsInstance(feed_manager, JSONFeedManager)

        # non-existing feeds
        with self.assertRaises(ValueError):
            _ = JSONFeedManager(['non-existing'])

    def test_download_feeds(self):
        """Test JSONFeedManager `download_feeds` method."""
        pass

    def test_download_recent_feeds(self):
        """Test JSONFeedManager `download_recent_feeds` method."""
        pass

    def test_load_feeds(self):
        """Test JSONFeedManager `load_feeds` method."""
        pass

    def test_feeds_check(self):
        """Test JSONFeedManager `feeds_check` method."""
        # existing

        feeds = ['recent', 2018]

        # should not raise
        _ = JSONFeedManager.feeds_check(feeds)

        # ---
        # non-existing

        feeds = ['nope', 'non-existing', 0, 1E+5]

        # should raise
        with self.assertRaises(ValueError):
            _ = JSONFeedManager.feeds_check(*feeds)

    def test_feed_exist(self):
        """Test JSONFeedManager `feed_exist` method."""
        # existing
        feeds = ['sample']
        _ = JSONFeedManager(feeds, data_dir='data/')

        # non-existing
        feeds = ['nope', 'too-old', 0]
        with self.assertRaises(ValueError):
            _ = JSONFeedManager(feeds)
