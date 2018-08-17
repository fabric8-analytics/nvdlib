"""Tests for manager module."""

import asyncio
import datetime
import os
import psutil
import tempfile
import unittest

from nvdlib.collection import Collection
from nvdlib.manager import FeedManager, JSONFeed, JSONFeedMetadata


_EVENT_LOOP = asyncio.get_event_loop()
_TEMP_DATA_DIR = tempfile.mkdtemp(prefix='tests_', suffix='_manager')


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

        # ---
        # non-existing, update=False

        feed_name = 'modified'
        meta = JSONFeedMetadata(feed_name=feed_name, data_dir=meta_temp_dir)

        # meta object created
        self.assertIsNotNone(meta)
        # should not be ready
        self.assertFalse(meta.is_downloaded())
        self.assertFalse(meta.is_parsed())
        self.assertFalse(meta.is_ready())

        # ---
        # non-existing, update=True

        meta = JSONFeedMetadata(
            feed_name=feed_name,
            data_dir=meta_temp_dir,
        )
        _EVENT_LOOP.run_until_complete(meta.update())

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


class TestFeed(unittest.TestCase):
    """Tests for Feed class."""

    def test___init__(self):
        """Test Feed initialization."""
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
        """Test Feed `download` method."""
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

    def test_load(self):
        """Test Feed `load` methods."""
        # test load existing
        feed_name = 'sample'
        json_feed = JSONFeed(feed_name, data_dir='data/')

        _EVENT_LOOP.run_until_complete(
            json_feed.load()
        )

        self.assertIsInstance(json_feed, JSONFeed)
        self.assertIsInstance(json_feed.data, dict)

        # ---
        # test download-load

        json_dir = tempfile.mkdtemp(dir=_TEMP_DATA_DIR)

        feed_name = 'modified'
        json_feed = JSONFeed(feed_name, data_dir=json_dir)

        _EVENT_LOOP.run_until_complete(
            json_feed.download(load=True)
        )

        self.assertIsInstance(json_feed, JSONFeed)
        self.assertIsInstance(json_feed.data, dict)

    def test_flush(self):
        """Test Feed `flush` method."""
        feed_name = 'sample'
        json_feed = JSONFeed(feed_name, data_dir='data/')

        # load the data
        _EVENT_LOOP.run_until_complete(json_feed.load())

        # feed should contain data already
        self.assertTrue(json_feed.data)

        process = psutil.Process()
        memory_usage = process.memory_info().rss

        # flush the data
        json_feed.flush()

        self.assertIsNone(json_feed.data)

        # sanity check -- lower memory usage
        self.assertLessEqual(process.memory_info().rss, memory_usage)


class TestFeedManager(unittest.TestCase):
    """Tests for FeedManager class."""

    def test___init__(self):
        """Test FeedManager initialization."""
        # ---
        # default
        feed_manager = FeedManager()
        self.assertIsInstance(feed_manager, FeedManager)

        # loop is closed
        self.assertTrue(feed_manager.event_loop.is_closed())

        default_loop = asyncio.get_event_loop()

        # ---
        # as context manager (hopefully default usage)
        with FeedManager() as feed_manager:
            self.assertIsInstance(feed_manager, FeedManager)
            # loop is running
            self.assertFalse(feed_manager.event_loop.is_closed())

            new_loop = feed_manager.event_loop

            # new context loop has been created
            self.assertNotEqual(id(new_loop), id(default_loop))
            # context has been taken over
            self.assertEqual(id(new_loop), id(asyncio.get_event_loop()))

        # check that context has been returned
        self.assertEqual(id(default_loop), id(asyncio.get_event_loop()))

        # should close after exitting context manager
        self.assertTrue(feed_manager.event_loop.is_closed())

    def test_download_feeds(self):
        """Test FeedManager `download_feeds` method."""
        feed_names = ['recent', 'modified']
        data_dir = tempfile.mkdtemp(dir=_TEMP_DATA_DIR)

        with FeedManager(data_dir=data_dir) as feed_manager:
            # non-existing
            feeds = feed_manager.download_feeds(feed_names)

            self.assertTrue(feeds)
            self.assertTrue(os.listdir(_TEMP_DATA_DIR))

            # existing, download-load
            feeds = feed_manager.download_feeds(['sample'],
                                                data_dir='data/',
                                                load=True)

            self.assertTrue(feeds)
            self.assertTrue(os.listdir(_TEMP_DATA_DIR))
            self.assertTrue(all(feed.is_loaded() for feed in feeds.values()))
            self.assertEqual(feeds, feed_manager.feeds)

    def test_load_feeds(self):
        """Test FeedManager `load_feeds` method."""
        # non-existing feeds, download-load
        feed_names = ['recent', 'modified']
        data_dir = tempfile.mkdtemp(dir=_TEMP_DATA_DIR)

        with FeedManager(data_dir=data_dir) as feed_manager:
            # unloaded feeds
            feed_manager.download_feeds(feed_names)

            # loaded the downloaded feeds
            # (maybe a lock on the tmp feed files would be a good idea
            #  for testing in unknown environment?)
            feeds = feed_manager.load_feeds(feed_names, data_dir=data_dir)

            self.assertTrue(feeds)
            self.assertTrue(os.listdir(_TEMP_DATA_DIR))
            self.assertTrue(all(feed.is_loaded() for feed in feeds.values()))

            # ---
            # existing

            # loaded feeds
            feeds = feed_manager.load_feeds(['sample'], data_dir='data/')

            self.assertTrue(feeds)
            self.assertTrue(all(feed.is_loaded() for feed in feeds.values()))

    def test_fetch_feeds(self):
        """Test FeedManager `fetch_feeds` method."""
        feed_names = ['recent', 'modified']
        data_dir = tempfile.mkdtemp(dir=_TEMP_DATA_DIR)

        with FeedManager(data_dir=data_dir) as feed_manager:
            # unloaded feeds
            feeds = feed_manager.fetch_feeds(feed_names)

            self.assertTrue(feeds)
            self.assertTrue(os.listdir(_TEMP_DATA_DIR))
            self.assertTrue(not any(feed.is_loaded() for feed in feeds.values()))

            # ---
            # existing

            # loaded feeds
            feeds = feed_manager.fetch_feeds(['sample'], data_dir='data/')

            self.assertTrue(feeds)
            self.assertTrue(not any(feed.is_loaded() for feed in feeds.values()))

    def test_collect(self):
        """Test FeedManager `collect` method."""
        feed_names = ['sample']

        with FeedManager(data_dir='data/') as feed_manager:
            # load feeds
            feed_dict = feed_manager.load_feeds(feed_names)
            feed_names = list(feed_dict.keys())
            feeds = list(feed_dict.values())

            self.assertEqual(feed_names, ['sample'])
            self.assertIsInstance(feeds[0], JSONFeed)

            # ---
            # query List[str]
            collector = feed_manager.collect(feed_names)

            self.assertIsInstance(collector, Collection)

            # query List[JSONFeed]
            collector = feed_manager.collect(feeds)

            self.assertIsInstance(collector, Collection)

    def test_feeds_check(self):
        """Test FeedManager `feeds_check` method."""
        # existing feeds, remote
        feeds = ['recent', 2018]

        # should not raise
        _ = FeedManager.feeds_check(*feeds)

        # ---
        # existing feeds, local
        FeedManager.feeds_check('sample', data_dir='data/')

        # ---
        # non-existing
        feeds = ['nope', 'non-existing', 0, 1E+5]

        # should raise
        with self.assertRaises(ValueError):
            _ = FeedManager.feeds_check(*feeds)

    def test_feeds_exist(self):
        """Test FeedManager `feeds_exist` method."""
        # existing
        feeds = ['sample']
        self.assertTrue(FeedManager.feeds_exist(*feeds, data_dir='data/'))

        # non-existing
        feeds = ['nope', 'too-old', 0]
        self.assertFalse(FeedManager.feeds_exist(feeds))
