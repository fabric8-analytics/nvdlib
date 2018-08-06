import asyncio
import aiofiles
import aiohttp
import concurrent.futures
import datetime
import fcntl
import gc
import gzip
import io
import json
import os
import sys

import typing
from typing import Union

from nvdlib import model, utils

# TODO(s):
# - use sqlite(?) in background, working with raw JSON files is slow and it gets overly complicated
# - better update logic
# - logging instead of prints


_XDG_DATA_HOME = os.environ.get('XDG_DATA_HOME', os.path.join(os.environ.get('HOME', '/tmp/'), '.local/share/'))
_DEFAULT_DATA_DIR = os.path.join(_XDG_DATA_HOME, 'nvd/')


class JSONFeedManager(object):

    MAX_NUM_WORKERS = 10

    def __init__(self, data_dir: str = None, n_workers: int = None):
        self._data_dir = data_dir or _DEFAULT_DATA_DIR
        self._n_workers = n_workers

        self._feed_names: typing.Set[str] = {'recent'}
        self._feeds: typing.Dict[str, JSONFeed] = dict()

        # create data_dir
        os.makedirs(self._data_dir, exist_ok=True)

        # create closed event loop (to be handled by context manager or explicitly set by user)
        self._loop: asyncio.BaseEventLoop = asyncio.new_event_loop()
        self._loop.close()

        # default context loop
        self._default_loop = asyncio.get_event_loop()

        # async event loop
        self._executor = concurrent.futures.ThreadPoolExecutor(
            max_workers=self._n_workers or self.MAX_NUM_WORKERS
        )

    def __enter__(self):
        self._default_loop = asyncio.get_event_loop()

        if self._loop.is_closed():
            self._loop = asyncio.new_event_loop()
            self._loop.set_default_executor(self._executor)

        # take over current context
        asyncio.set_event_loop(self._loop)

        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        # close event loop
        self._loop.stop()
        self._loop.close()

        # return context to default asyncio loop
        asyncio.set_event_loop(self._default_loop)

        # flush all feeds
        for feed in self._feeds.values():
            feed.flush()

    @property
    def feed_names(self) -> list:
        return list(self._feed_names)

    @property
    def feeds(self) -> dict:
        return self._feeds

    @property
    def event_loop(self):
        return self._loop

    def set_event_loop(self, loop: asyncio.BaseEventLoop):
        self._loop = loop

    def download_feeds(self, feed_names: typing.List[Union[str, int]], data_dir: str = None, load=False):
        """Asynchronously download JSON feeds."""
        self.feeds_check(*feed_names, data_dir=data_dir)

        futures = [
            JSONFeed(feed_name=feed, data_dir=data_dir or self._data_dir).download(
                loop=self._loop,
                load=load
            )
            for feed in feed_names
        ]
        tasks = asyncio.gather(*futures)
        feeds = self._loop.run_until_complete(tasks)

        self._feed_names = set([feed.name for feed in feeds])

        if load:
            self._feeds = {feed.name: feed for feed in feeds}

        return feeds

    def download_recent_feed(self, data_dir: str = None):
        """Asynchronously download recent JSON feed.

        Convenient wrapper around `download_feeds` method.
        """
        return self.download_feeds(['recent'], data_dir=data_dir)

    def download_modified_feed(self, data_dir: str = None):
        """Asynchronously download modified JSON feed.

        Convenient wrapper around `download_feeds` method.
        """
        return self.download_feeds(['modified'], data_dir=data_dir)

    def load_feeds(self, feed_names, data_dir: str = None):
        """Asynchronously load existing JSON feeds."""
        self.feeds_check(*feed_names, data_dir=data_dir)

        futures = [
            JSONFeed(feed_name=feed, data_dir=data_dir or self._data_dir).load(
                loop=self._loop,
            )
            for feed in feed_names
        ]
        tasks = asyncio.gather(*futures)
        feeds = self._loop.run_until_complete(tasks)

        return feeds

    @staticmethod
    def feeds_check(*feed_names, data_dir: str = None, loop: asyncio.BaseEventLoop = None):
        """Check feeds for name validity.

        :raises: ValueError if any feed name is invalid
        """
        loop = loop or asyncio.get_event_loop()

        # remove local feeds
        distinct_feeds = list(
            filter(lambda f: not JSONFeedManager.feeds_exist(f, data_dir=data_dir, loop=loop), feed_names)
        )

        futures = [
            JSONFeedMetadata.url_exists(feed, loop=loop)
            for feed in distinct_feeds
        ]
        tasks = asyncio.gather(*futures)

        results = loop.run_until_complete(tasks)
        invalid = [
            feed for valid, feed in zip(results, distinct_feeds)
            if not valid
        ]

        if any(invalid):
            raise ValueError(
                f"Invalid feeds found: {invalid}"
            )

    @staticmethod
    def feeds_exist(*feed_names, data_dir: str = None, loop: asyncio.BaseEventLoop = None):
        """Check feeds whether exist locally.

        :raises: ValueError if feed does not exist.
        """
        loop = loop or asyncio.get_event_loop()

        futures = [
            JSONFeedMetadata.metadata_exist(feed, data_dir=data_dir, loop=loop)
            for feed in feed_names
        ]
        tasks = asyncio.gather(*futures)

        results = loop.run_until_complete(tasks)
        for valid, feed in zip(results, feed_names):
            if not valid:
                return False

        return True

    @staticmethod
    def get_default_event_loop():
        loop = asyncio.new_event_loop()
        executor = concurrent.futures.ThreadPoolExecutor(
            max_workers=JSONFeedManager.MAX_NUM_WORKERS
        )
        loop.set_default_executor(executor)

        return loop


class JSONFeed(object):

    DATA_URL_TEMPLATE = 'https://static.nvd.nist.gov/feeds/json/cve/1.0/nvdcve-1.0-{feed}.json.gz'

    def __init__(self, feed_name: str, data_dir: str = None):
        self._name = feed_name
        self._data = None

        self._data_dir = data_dir or _DEFAULT_DATA_DIR

        self._data_url = self.DATA_URL_TEMPLATE.format(feed=self._name)
        self._data_filename = 'nvdcve-1.0-{feed}.json'.format(feed=self._name)
        self._data_path = os.path.join(self._data_dir, self._data_filename)

        self._metadata = JSONFeedMetadata(
            feed_name=self._name,
            data_dir=self._data_dir
        )

        self._is_downloaded = os.path.isfile(self._data_path)
        self._is_loaded = False

    @property
    def name(self):
        return self._name

    @property
    def data(self):
        return self._data

    @property
    def sha256(self):
        return utils.compute_sha256(self._data_path)

    @property
    def filename(self):
        return self._data_filename

    @property
    def path(self):
        return self._data_path

    def is_loaded(self):
        return self._is_loaded

    def is_downloaded(self):
        return self._is_downloaded

    def is_ready(self):
        return self._is_downloaded and self._is_loaded

    async def download(self, loop: asyncio.BaseEventLoop = None, load=False):
        """Download the JSON feed asynchronously and return JSONFeed object."""
        # get current metadata
        await self._metadata.fetch(loop)

        self._metadata.parse()

        if self._is_downloaded:
            # check sha256
            data_sha256 = utils.compute_sha256(self.path)
            if data_sha256 == self._metadata.sha256:
                # already up to date
                print(f"Feed `{self._name}` is already up to date.", file=sys.stderr)

                if load:
                    await self.load(loop)

                return self

        await self._metadata.save()

        loop = loop or asyncio.get_event_loop()

        print('Downloading ...', file=sys.stderr)

        data: bytes
        async with aiohttp.ClientSession(loop=loop) as session:
            async with session.get(self._data_url) as response:
                if response.status != 200:
                    raise IOError('Unable to download {feed} feed.'.format(feed=self._name))

                data = await response.read()

        gzip_file = io.BytesIO()
        gzip_file.write(data)
        gzip_file.seek(0)

        json_stream = gzip.GzipFile(fileobj=gzip_file, mode='rb').read()

        print('Writing ...', file=sys.stderr)

        async with aiofiles.open(self._data_path, 'wb', loop=loop) as f:
            fcntl.flock(f, fcntl.LOCK_EX | fcntl.LOCK_NB)
            await f.write(json_stream)
            await f.flush()
            fcntl.flock(f, fcntl.LOCK_UN)

        if load:
            self._data = json.loads(json_stream)
            self._is_loaded = True

        self._is_downloaded = True

        print(f"Finished downloading feed `{self._name}`", file=sys.stderr)

        return self

    async def load(self, loop: asyncio.BaseEventLoop = None):
        """Load the JSON feed asynchronously into memory."""
        if not self._is_downloaded:
            raise FileNotFoundError(
                f"Cannot load feed: `{self._name}`, "
                f"data not present in `{self._data_path}`."
            )

        loop = loop or asyncio.get_event_loop()

        if not self._is_loaded:
            async with aiofiles.open(self._data_path, 'r', loop=loop) as f:
                self._data = json.loads(await f.read())
                asyncio.sleep(0.1)
                self._is_loaded = True

        return self

    def flush(self):
        """Flush the data held by JSONFeed and garbage collect to release memory."""
        del self._data
        self._data = None

        # explicitly run garbage collector (just in case)
        gc.collect()


class JSONFeedMetadata(object):

    METADATA_URL_TEMPLATE = "https://nvd.nist.gov/feeds/json/cve/1.0/nvdcve-1.0-{feed}.meta"
    METADATA_FILE_TEMPLATE = "nvdcve-1.0-{feed}.meta"

    def __init__(self, feed_name, data_dir=None):
        self._name = feed_name

        self._data_raw = None
        self._data = None

        self._data_dir = data_dir or _DEFAULT_DATA_DIR

        self._metadata_url = self.METADATA_URL_TEMPLATE.format(feed=self._name)
        self._metadata_filename = self.METADATA_FILE_TEMPLATE.format(feed=self._name)
        self._metadata_path = os.path.join(self._data_dir, self._metadata_filename)

        self._last_modified: datetime.datetime = None
        self._size: int = None
        self._zip_size: int = None
        self._gz_size: int = None
        self._sha256: str = None

        self._is_downloaded = os.path.isfile(self._metadata_path)
        self._is_parsed = False

        if self._is_downloaded:
            with open(self._metadata_path, 'r') as f:
                self._data = f.read()
                self._data_raw = self._data

                metadata_dict = self.parse_metadata(self._data)

                # update keys
                self.__dict__.update({"_{key}".format(key=x): metadata_dict[x] for x in metadata_dict})
                self._is_parsed = True

    def __str__(self):
        return "[metadata:{feed}] sha256:{sha256} ({last_modified})".format(feed=self._name,
                                                                            sha256=self._sha256,
                                                                            last_modified=self._last_modified)

    @property
    def data(self) -> typing.Union[str, dict, None]:
        return self._data

    @property
    def raw_data(self) -> typing.Union[str, None]:
        return self._data_raw

    @property
    def sha256(self):
        return self._sha256.lower()

    @property
    def filename(self):
        return self._metadata_filename

    @property
    def path(self):
        return self._metadata_path

    def is_parsed(self):
        return self._is_parsed

    def is_downloaded(self):
        return self._is_downloaded

    def is_ready(self):
        return self._is_downloaded and self._is_parsed

    async def fetch(self, loop: asyncio.BaseEventLoop = None):
        """Fetch NVD Feed metadata.

        :returns: self
        """
        loop = loop or asyncio.get_event_loop()

        if await self.url_exists(self._name):
            async with aiohttp.ClientSession(loop=loop) as session:
                async with session.get(self._metadata_url) as response:
                    if response.status != 200:
                        raise Exception(
                            f"Unable to download {self._name} feed metadata."
                        )

                    self._data_raw = await response.text('utf-8')

        elif await self.metadata_exist(self._name, self._data_dir, loop=loop):
            async with aiofiles.open(self._metadata_path, 'r', loop=loop) as f:
                self._data_raw = await f.read()

        else:
            raise ValueError(f"Feed `{self._name}` does not exist.")

        self._data = self._data_raw
        self._is_downloaded = True

        return self

    def parse(self):
        """Parse metadata held by the current object.

        :returns: self
        """
        if not self._is_parsed:
            self._data = self.parse_metadata(self.data)

        self._is_parsed = True

        return self

    async def save(self, data_dir: str = None, loop: asyncio.BaseEventLoop = None):
        """Save metadata into .meta file.

        :returns: self
        """
        loop = loop or asyncio.get_event_loop()

        if data_dir:
            self._data_dir = data_dir
            self._metadata_path = os.path.join(self._data_dir, self._metadata_filename)

        async with aiofiles.open(self._metadata_path, 'w', loop=loop) as f:
            fcntl.flock(f, fcntl.LOCK_EX | fcntl.LOCK_NB)
            await f.write(self._data_raw)
            asyncio.sleep(0.1)
            await f.flush()
            fcntl.flock(f, fcntl.LOCK_UN)

        self._is_downloaded = True

        return self

    async def update(self,
                     metadata: dict = None,
                     data_dir: str = None,
                     save=True,
                     loop: asyncio.BaseEventLoop = None):
        """Fetches and updates metadata.

        :param metadata: dict, if not specified, fetches metadata from NVD
        :param data_dir: str, metadata directory
        :param save: bool, whether to save metadata locally (Default: True)

            If not specified, uses directory used during object initialization.
            If provided, overrides permanently data directory passed during initialization.

        :param loop: asynchronous event loop

            If not specified, default loop is created using asyncio.get_event_loop(). It is highly
            recommended to use an explicit loop.

        :returns: self
        """
        loop = loop or asyncio.get_event_loop()

        if data_dir:
            self._data_dir = data_dir
            self._metadata_path = os.path.join(self._data_dir, self._metadata_filename)

        os.makedirs(self._data_dir, exist_ok=True)

        if not metadata:
            # fetch
            await self.fetch(loop=loop)

            # parse
            self.parse()
            metadata = self.data

            meta_exists = await self.metadata_exist(
                feed_name=self._name,
                data_dir=self._data_dir,
                sha256=metadata.get('sha256', None),
                loop=loop
            )

            if not meta_exists and save:
                await self.save()

        if not metadata.get('sha256'):
            raise ValueError("Invalid metadata file for {feed} data feed.".format(feed=self._name))

        # update keys
        self.__dict__.update({"_{key}".format(key=x): metadata[x] for x in metadata})
        self._is_parsed = True

        return self

    @classmethod
    async def url_exists(cls, feed_name: str,
                         loop: asyncio.BaseEventLoop = None):
        """Asynchronously check whether url for given feed metadata exists."""
        metadata_url = cls.METADATA_URL_TEMPLATE.format(feed=feed_name)
        loop = loop or asyncio.get_event_loop()

        async with aiohttp.ClientSession(loop=loop) as session:
            async with session.head(metadata_url) as response:
                return response.status == 200

    @classmethod
    async def metadata_exist(cls,
                             feed_name: str,
                             data_dir: str = None,
                             sha256: str = None,
                             loop: asyncio.BaseEventLoop = None):
        """Asynchronously check whether metadata exists locally."""
        data_dir = data_dir or _DEFAULT_DATA_DIR

        metadata_filename = cls.METADATA_FILE_TEMPLATE.format(feed=feed_name)
        metadata_path = os.path.join(data_dir, metadata_filename)

        exists = os.path.exists(metadata_path)

        if exists and sha256:
            # check sha265
            async with aiofiles.open(metadata_path, 'r', loop=loop) as f:
                metadata = await f.read()

            parsed_existing = cls.parse_metadata(metadata)
            exists = sha256 == parsed_existing['sha256']

        return exists

    @staticmethod
    def parse_metadata(metadata: str):

        metadata_dict = {
            'last_modified': None,
            'size': None,
            'zipSize': None,
            'gzSize': None,
            'sha256': None
        }

        for line in metadata.split('\n'):
            line = line.strip()
            if not line:
                # empty line, skip
                continue
            key, value = line.split(':', maxsplit=1)
            key = key.strip()
            value = value.strip()

            if key == 'lastModifiedDate':
                time_format = "%Y-%m-%dT%H:%M:%S"
                time_string = "-".join(value.split(sep='-')[:-1])
                time_object = datetime.datetime.strptime(time_string, time_format)

                metadata_dict['last_modified'] = time_object
            elif key == 'size':
                metadata_dict['size'] = int(value)
            elif key == 'zipSize':
                metadata_dict['zipSize'] = int(value)
            elif key == 'gzSize':
                metadata_dict['gzSize'] = int(value)
            elif key == 'sha256':
                metadata_dict['sha256'] = value

        return metadata_dict
