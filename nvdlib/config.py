import os

# constants
XDG_DATA_HOME = os.environ.get('XDG_DATA_HOME', os.path.join(os.environ.get('HOME', '/tmp/'), '.local/share/'))
DEFAULT_DATA_DIR = os.path.join(XDG_DATA_HOME, 'nvd/')

# logging
DEFAULT_LOGGING_LEVEL = os.environ.get('DEFAULT_LOGGING_LEVEL', 'WARNING')

# adapter
ADAPTER = os.environ.get('ADAPTER', 'DEFAULT')

# download
FEED_DOWNLOAD_TIMEOUT = 300  # seconds
