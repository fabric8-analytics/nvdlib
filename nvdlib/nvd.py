import asyncio
import aiofiles
import aiohttp
import concurrent.futures
import datetime
import gc
import gzip
import io
import json
import os
import sys
import typing

from nvdlib import model, utils

# TODO(s):
# - use sqlite(?) in background, working with raw JSON files is slow and it gets overly complicated
# - better update logic


_XDG_DATA_HOME = os.environ.get('XDG_DATA_HOME', os.path.join(os.environ.get('HOME', '/tmp/'), '.local/share/'))
_DEFAULT_DATA_DIR = os.path.join(_XDG_DATA_HOME, 'nvd/')

# async event loop setup
_MAX_NUM_WORKERS = 10

_LOOP = asyncio.get_event_loop()
_EXECUTOR = concurrent.futures.ThreadPoolExecutor(
    max_workers=_MAX_NUM_WORKERS
)
_LOOP.set_default_executor(_EXECUTOR)

# async http client setup
_CLIENT = aiohttp.ClientSession(loop=_LOOP)


class JSONFeedManager(object):

    def __init__(self, feed_names: list = None, data_dir: str = None):
        self._feeds = set(feed_names or ['recent'])
        self._data_dir = data_dir or _DEFAULT_DATA_DIR

        self.feeds_check(*self._feeds, data_dir=self._data_dir)

    @property
    def feeds(self):
        return self._feeds

    def download_feeds(self, *feed_names, data_dir=None):
        pass

    def download_recent_feeds(self, data_dir=None):
        pass

    def load_feeds(self, feed_names, data_dir=None):
        pass

    @classmethod
    def feeds_check(cls, *feed_names, data_dir=None):
        """Check feeds for name validity.

        :raises: ValueError if any feed name is invalid
        """
        # remove local feeds
        distinct_feeds = list(
            filter(lambda f: not cls.feeds_exist(f, data_dir=data_dir), feed_names)
        )

        futures = [
            JSONFeedMetadata.url_exists(feed)
            for feed in distinct_feeds
        ]
        tasks = asyncio.gather(*futures)

        results = _LOOP.run_until_complete(tasks)
        invalid = [
            feed for valid, feed in zip(results, distinct_feeds)
            if not valid
        ]

        if any(invalid):
            raise ValueError(
                f"Invalid feeds found: {invalid}"
            )

    @staticmethod
    def feeds_exist(*feed_names, data_dir: str = None):
        """Check feeds whether exist locally.

        :raises: ValueError if feed does not exist.
        """
        futures = [
            JSONFeedMetadata.metadata_exist(feed, data_dir=data_dir)
            for feed in feed_names
        ]
        tasks = asyncio.gather(*futures)

        results = _LOOP.run_until_complete(tasks)
        for valid, feed in zip(results, feed_names):
            if not valid:
                return False

        return True


class JSONFeed(object):

    DATA_URL_TEMPLATE = 'https://static.nvd.nist.gov/feeds/json/cve/1.0/nvdcve-1.0-{feed}.json.gz'

    def __init__(self, feed_name, data_dir=None):
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

        # instance-bound methods
        self.load = self.__load
        self.download = self.__download

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

    @classmethod
    def download(cls,
                 feed_name: str = None,
                 data_dir: str = None,
                 load=False):

        feed = cls(feed_name, data_dir)
        feed = _LOOP.run_until_complete(feed.download(load=load))

        return feed

    @classmethod
    def load(cls,
             feed_name: str = None,
             data_dir: str = None,
             update=False):
        """Load an existing feed into memory.

        NOTE: The feed has to be present in `data_dir`.
        """
        if update:
            feed = cls.download(feed_name, data_dir)
        else:
            feed = cls(feed_name, data_dir)

        if not feed._is_downloaded:
            raise FileNotFoundError(
                f"Cannot load feed: `{feed}`, "
                f"data not present in `{data_dir}`."
            )

        if not feed._is_loaded:
            with open(feed._data_path) as f:
                feed._data = json.load(f)
                feed._is_loaded = True

        return feed

    def is_loaded(self):
        return self._is_loaded

    def is_downloaded(self):
        return self._is_downloaded

    def is_ready(self):
        return self._is_downloaded and self._is_loaded

    async def __load(self):
        """Load the JSON feed asynchronously into memory."""
        if not self._is_downloaded:
            raise FileNotFoundError(
                f"Cannot load feed: `{self._name}`, "
                f"data not present in `{self._data_path}`."
            )

        if not self._is_loaded:
            async with aiofiles.open(self._data_path, 'r') as f:
                self._data = json.loads(await f.read())
                self._is_loaded = True

        return self

    async def __download(self, load=False):
        """Download the JSON feed asynchronously and return JSONFeed object."""
        # get current metadata
        await self._metadata.fetch()
        self._metadata.parse()

        if self._is_downloaded:
            # check sha256
            data_sha256 = utils.compute_sha256(self.path)
            if data_sha256 == self._metadata.sha256:
                # already up to date
                print(f"Feed `{self._name}` is already up to date.", file=sys.stderr)

                if load:
                    self.load()

                return self

        await self._metadata.save()

        print('Downloading ...', file=sys.stderr)

        data: bytes
        async with _CLIENT.get(self._data_url) as response:
            if response.status != 200:
                raise IOError('Unable to download {feed} feed.'.format(feed=self._name))

            data = await response.read()

        gzip_file = io.BytesIO()
        gzip_file.write(data)
        gzip_file.seek(0)

        json_file = gzip.GzipFile(fileobj=gzip_file, mode='rb')

        async with aiofiles.open(self._data_path, 'wb') as f:
            stream = json_file.read()
            await f.write(stream)
            await f.flush()

        if load:
            self._data = json.loads(stream)
            self._is_loaded = True

        self._is_downloaded = True

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

    def __init__(self, feed_name, data_dir=None, update=False):
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

                _LOOP.run_until_complete(self.update(metadata_dict, save=False))

                self._is_parsed = True

        if update:
            _LOOP.run_until_complete(self.update())

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

    async def fetch(self):
        """Fetch NVD Feed metadata.

        :returns: self
        """
        if await self.url_exists(self._name):

            async with _CLIENT.get(self._metadata_url) as response:
                if response.status != 200:
                    raise Exception(
                        f"Unable to download {self._name} feed metadata."
                    )

                self._data_raw = await response.text('utf-8')

        elif await self.metadata_exist(self._name, self._data_dir):
            async with aiofiles.open(self._metadata_path) as f:
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

    async def save(self, data_dir: str = None):
        """Save metadata into .meta file.

        :returns: self
        """
        if data_dir:
            self._data_dir = data_dir
            self._metadata_path = os.path.join(self._data_dir, self._metadata_filename)

        async with aiofiles.open(self._metadata_path, 'w') as f:
            await f.write(self._data_raw)
            await f.flush()

        self._is_downloaded = True

        return self

    async def update(self, metadata: dict = None, data_dir: str = None, save=True):
        """Fetches and updates metadata.

        :param metadata: dict, if not specified, fetches metadata from NVD
        :param data_dir: str, metadata directory
        :param save: bool, whether to save metadata locally (Default: True)

            If not specified, uses directory used during object initialization.
            If provided, overrides permanently data directory passed during initialization.

        :returns: self
        """
        if data_dir:
            self._data_dir = data_dir
            self._metadata_path = os.path.join(self._data_dir, self._metadata_filename)

        os.makedirs(self._data_dir, exist_ok=True)

        if not metadata:
            # fetch
            await self.fetch()

            # parse
            self.parse()
            metadata = self.data

            meta_exists = await self.metadata_exist(
                feed_name=self._name,
                data_dir=self._data_dir,
                sha256=metadata.get('sha256', None)
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
    async def url_exists(cls, feed_name):
        """Asynchronously check whether url for given feed metadata exists."""
        metadata_url = cls.METADATA_URL_TEMPLATE.format(feed=feed_name)

        async with _CLIENT.head(metadata_url) as response:
            return response.status == 200

    @classmethod
    async def metadata_exist(cls, feed_name: str, data_dir: str = None, sha256: str = None):
        """Asynchronously check whether metadata exists locally."""
        data_dir = data_dir or _DEFAULT_DATA_DIR

        metadata_filename = cls.METADATA_FILE_TEMPLATE.format(feed=feed_name)
        metadata_path = os.path.join(data_dir, metadata_filename)

        exists = os.path.exists(metadata_path)

        if exists and sha256:
            # check sha265
            async with aiofiles.open(metadata_path, 'r') as f:
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
