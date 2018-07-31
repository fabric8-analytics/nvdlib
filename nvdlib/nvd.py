import asyncio
import datetime
import gzip
import hashlib
import io
import json
import os
import requests

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
            self._feeds = tuple(JsonFeed(x) for x in feed_names)
        else:
            this_year = datetime.datetime.now().year
            self._feeds = tuple(JsonFeed(str(x)) for x in range(2002, this_year))

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

    def __init__(self, feed_name, data_dir=None):
        self._name = feed_name

        self._data_dir = data_dir or _DEFAULT_DATA_DIR
        self._data_filename = 'nvdcve-1.0-{feed}.json'.format(feed=self._name)
        self._data_path = os.path.join(self._data_dir, self._data_filename)
        self._data_url = self._DATA_URL_TEMPLATE.format(feed=self._name)

        self._metadata = JSONFeedMetadata(self._name, self._data_dir)

    @property
    def name(self):
        return self._name

    def downloaded(self):
        return os.path.exists(self._data_path) and os.path.isfile(self._data_path)

    def download(self):
        self._metadata.update()

        if self.downloaded():
            data_sha256 = self._compute_sha256()
            if data_sha256 == self._metadata.sha256:
                # already up-to-date
                return

        response = requests.get(self._data_url)
        if response.status_code != 200:
            raise IOError('Unable to download {feed} feed.'.format(feed=self._name))

        gzip_file = io.BytesIO()
        gzip_file.write(response.content)
        gzip_file.seek(0)

        json_file = gzip.GzipFile(fileobj=gzip_file, mode='rb')

        with open(self._data_path, 'wb') as f:
            f.write(json_file.read())

    def cves(self):
        # TODO: stream the json(?), cache in memory
        with open(self._data_path, 'r', encoding='utf-8') as f:
            data = json.load(f).get('CVE_Items', [])

        for cve_dict in data:
            cve = model.CVE.from_dict(cve_dict)
            yield cve

    def get_cve(self, cve_id):
        for cve in self.cves():
            if cve.cve_id == cve_id:
                return cve
        return None

    def _compute_sha256(self):
        sha256 = hashlib.sha256()
        with open(self._data_path, 'rb') as f:
            while True:
                data = f.read(4096)
                if not data:
                    break
                sha256.update(data)
        return sha256.hexdigest().lower()

    def __str__(self):
        return self.name


class JSONFeedMetadata(object):

    _METADATA_URL_TEMPLATE = "https://nvd.nist.gov/feeds/json/cve/1.0/nvdcve-1.0-{feed}.meta"
    _METADATA_FILE_TEMPLATE = "nvdcve-1.0-{feed}.meta"

    def __init__(self, feed_name, data_dir=None, update=False):
        self._name = feed_name

        self._data_dir = data_dir or _DEFAULT_DATA_DIR

        self._metadata_url = self._METADATA_URL_TEMPLATE.format(feed=self._name)
        self._metadata_filename = self._METADATA_FILE_TEMPLATE.format(feed=self._name)
        self._metadata_path = os.path.join(self._data_dir, self._metadata_filename)

        self._last_modified: datetime.datetime = None
        self._size: int = None
        self._zip_size: int = None
        self._gz_size: int = None
        self._sha256: str = None

        self._is_downloaded = os.path.exists(self._metadata_path) and os.path.isfile(self._metadata_path)

        self._is_parsed = False

        if self._is_downloaded:
            with open(self._metadata_path, 'r') as f:
                data = self.parse_metadata(f.read())
                self.update(data)

                self._is_parsed = True

        if update:
            self.update()

            self._is_parsed = True
            self._is_downloaded = True

    def __str__(self):
        return "[metadata:{feed}] sha256:{sha256} ({last_modified})".format(feed=self._name,
                                                                            sha256=self._sha256,
                                                                            last_modified=self._last_modified)

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

    def fetch(self) -> str:
        """Fetch NVD Feed metadata."""
        if not self.url_exists(self._name):
            raise ValueError(f"Feed `{self._name}` does not exist.")

        response = requests.get(self._metadata_url)
        if response.status_code != 200:
            raise Exception('Unable to download {feed} feed metadata.'.format(feed=self._name))

        return response.text

    def update(self, metadata: dict = None, data_dir: str = None):
        """Fetches and updates metadata.

        :param metadata: dict, if not specified, fetches metadata from NVD
        :param data_dir: str, metadata directory

            If not specified, uses directory used during object initialization.
            If provided, overrides permanently data directory passed during initialization.
        """
        if data_dir:
            self._data_dir = data_dir
            self._metadata_path = os.path.join(self._data_dir, self._metadata_filename)

        os.makedirs(self._data_dir, exist_ok=True)

        if not metadata:
            metadata: str = self.fetch()

        data: dict = self.parse_metadata(metadata)

        if not data.get('sha256'):
            raise ValueError("Invalid metadata file for {feed} data feed.".format(feed=self._name))

        if not self.metadata_exist(feed_name=self._name, data_dir=self._data_dir, sha256=data['sha256']):
            with open(self._metadata_path, 'w') as f:
                f.write(metadata)

            self._is_downloaded = True

        metadata_dict = {"_{key}".format(key=x): data[x] for x in data}
        self.__dict__.update(metadata_dict)
        self._is_parsed = True

    @classmethod
    def url_exists(cls, feed_name):
        metadata_url = cls._METADATA_URL_TEMPLATE.format(feed=feed_name)
        response = requests.head(metadata_url)

        return response.status_code == 200

    @classmethod
    def metadata_exist(cls, feed_name: str, sha256: int = None, data_dir: str = None):

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
    def parse_metadata(metadata):

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
