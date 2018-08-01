import datetime
import gc
import gzip
import io
import json
import os
import requests
import sys
import typing

from nvdlib import model, utils

# TODO(s):
# - use sqlite(?) in background, working with raw JSON files is slow and it gets overly complicated
# - better update logic


_XDG_DATA_HOME = os.environ.get('XDG_DATA_HOME', os.path.join(os.environ.get('HOME', '/tmp/'), '.local/share/'))
_DEFAULT_DATA_DIR = os.path.join(_XDG_DATA_HOME, 'nvd/')


class NVD(object):

    def __init__(self, data_dir=None, feed_names=None):
        self._data_dir = _DEFAULT_DATA_DIR
        if data_dir:
            self._data_dir = data_dir

        self._feeds = ()
        if feed_names:
            self._feeds = tuple(JSONFeed(x) for x in feed_names)
        else:
            this_year = datetime.datetime.now().year
            self._feeds = tuple(JSONFeed(str(x)) for x in range(2002, this_year))

    def update(self):
        """Update feeds."""
        for feed in self.feeds:
            # We don't really do updates now, we just download the latest gzip.
            feed.download()

    def get_cve(self, cve_id):
        """Return `model.CVE` for given CVE ID.

        Returns None if the CVE record was not found in currently selected feeds.
        """
        parts = cve_id.split('-')
        if len(parts) != 3:
            raise ValueError('Invalid CVE ID format: {cve_id}'.format(cve_id=cve_id))

        feed_candidates = []
        feed_name = parts[1]
        for f in self.feeds:
            if f.name == feed_name or f.name in ('recent', 'modified'):
                feed_candidates.append(f)

        for feed in feed_candidates:
            cve = feed.get_cve(cve_id)
            if cve is not None:
                return cve

    def cves(self):
        """Returns generator for iterating over all CVE entries in currently selected feeds."""
        for feed in self.feeds:
            for cve in feed.cves():
                yield cve

    @property
    def feeds(self):
        return self._feeds

    @classmethod
    def feed_exists(cls, feed_name):
        return JSONFeedMetadata.url_exists(feed_name)

    @classmethod
    def from_feeds(cls, feed_names, data_dir=None):
        return cls(data_dir=data_dir, feed_names=feed_names)

    @classmethod
    def from_recent(cls, data_dir=None):
        return cls(feed_names=['recent'], data_dir=data_dir)


class JSONFeed(object):

    _DATA_URL_TEMPLATE = 'https://static.nvd.nist.gov/feeds/json/cve/1.0/nvdcve-1.0-{feed}.json.gz'

    def __init__(self, feed_name, data_dir=None, load=False, update=False):
        self._name = feed_name
        self._data = None

        self._data_dir = data_dir or _DEFAULT_DATA_DIR

        self._data_url = self._DATA_URL_TEMPLATE.format(feed=self._name)
        self._data_filename = 'nvdcve-1.0-{feed}.json'.format(feed=self._name)
        self._data_path = os.path.join(self._data_dir, self._data_filename)

        self._metadata = JSONFeedMetadata(
            feed_name=self._name,
            data_dir=self._data_dir
        )

        self._is_downloaded = not update and os.path.isfile(self._data_path)
        self._is_loaded = False

        if load:
            if not self._is_downloaded:
                self.download(load=True)
            else:
                self.__load()

        # instance-bound methods
        self.load = self.__load

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

    @property
    def name(self):
        return self._name

    def download(self, load=False):
        # get current metadata
        self._metadata.fetch()
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

        self._metadata.save()

        print('Downloading ...', file=sys.stderr)
        response = requests.get(self._data_url)
        if response.status_code != 200:
            raise IOError('Unable to download {feed} feed.'.format(feed=self._name))

        gzip_file = io.BytesIO()
        gzip_file.write(response.content)
        gzip_file.seek(0)

        json_file = gzip.GzipFile(fileobj=gzip_file, mode='rb')

        with open(self._data_path, 'wb') as f:
            stream = json_file.read()
            f.write(stream)
            if load:
                self._data = json.loads(stream)
                self._is_loaded = True

        self._is_downloaded = True

        return self

    @classmethod
    def load(cls, feed_name=None, data_dir: str = None):
        """Load the JSON feed into memory and return JSONFeed object."""
        return cls(feed_name=feed_name, data_dir=data_dir, load=True, update=False)

    def __load(self):
        """Load an existing feed into memory.

        NOTE: The feed has to be present in `data_dir`.
        """
        if not self._is_loaded:
            with open(self._data_path) as f:
                self._data = json.load(f)
                self._is_loaded = True

        return self

    def flush(self):
        """Flush the data held by JSONFeed and garbage collect to release memory."""
        del self._data
        self._data = None

        # explicitly run garbage collector (just in case)
        gc.collect()


class JSONFeedMetadata(object):

    _METADATA_URL_TEMPLATE = "https://nvd.nist.gov/feeds/json/cve/1.0/nvdcve-1.0-{feed}.meta"
    _METADATA_FILE_TEMPLATE = "nvdcve-1.0-{feed}.meta"

    def __init__(self, feed_name, data_dir=None, update=False):
        self._name = feed_name

        self._data_raw = None
        self._data = None

        self._data_dir = data_dir or _DEFAULT_DATA_DIR

        self._metadata_url = self._METADATA_URL_TEMPLATE.format(feed=self._name)
        self._metadata_filename = self._METADATA_FILE_TEMPLATE.format(feed=self._name)
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

                self.update(metadata_dict, save=False)

                self._is_parsed = True

        if update:
            self.update()

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

    def fetch(self):
        """Fetch NVD Feed metadata.

        :returns: self
        """
        if self.url_exists(self._name):

            response = requests.get(self._metadata_url)
            if response.status_code != 200:
                raise Exception('Unable to download {feed} feed metadata.'.format(feed=self._name))

            self._data_raw = response.text

        elif self.metadata_exist(self._name, self._data_dir):
            with open(self._metadata_path) as f:
                self._data_raw = f.read()

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

    def save(self, data_dir: str = None):
        """Save metadata into .meta file.

        :returns: self
        """
        if data_dir:
            self._data_dir = data_dir
            self._metadata_path = os.path.join(self._data_dir, self._metadata_filename)

        with open(self._metadata_path, 'w') as f:
            f.write(self._data_raw)

        self._is_downloaded = True

        return self

    def update(self, metadata: dict = None, data_dir: str = None, save=True):
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
            self.fetch()

            # parse
            self.parse()
            metadata = self.data

            meta_exists = self.metadata_exist(
                feed_name=self._name,
                data_dir=self._data_dir,
                sha256=metadata.get('sha256', None)
            )

            if not meta_exists and save:
                self.save()

        if not metadata.get('sha256'):
            raise ValueError("Invalid metadata file for {feed} data feed.".format(feed=self._name))

        # update keys
        self.__dict__.update({"_{key}".format(key=x): metadata[x] for x in metadata})
        self._is_parsed = True

        return self

    @classmethod
    def url_exists(cls, feed_name):
        metadata_url = cls._METADATA_URL_TEMPLATE.format(feed=feed_name)
        response = requests.head(metadata_url)

        return response.status_code == 200

    @classmethod
    def metadata_exist(cls, feed_name: str, data_dir: str = None, sha256: str = None):

        data_dir = data_dir or _DEFAULT_DATA_DIR
        metadata_filename = cls._METADATA_FILE_TEMPLATE.format(feed=feed_name)
        metadata_path = os.path.join(data_dir, metadata_filename)

        exists = os.path.exists(metadata_path)

        if exists and sha256:
            # check sha265
            parsed_existing = cls.parse_metadata(metadata_path)
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
