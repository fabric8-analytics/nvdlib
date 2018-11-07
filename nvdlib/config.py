import os
from pathlib import Path

# constants
XDG_DATA_HOME = os.environ.get('XDG_DATA_HOME', Path(os.environ.get('HOME', '/tmp/')) / '.local/share/')
DEFAULT_DATA_DIR = Path(XDG_DATA_HOME) / 'nvd/'

# logging
DEFAULT_LOGGING_LEVEL = os.environ.get('DEFAULT_LOGGING_LEVEL', 'WARNING')

# adapter
ADAPTER = os.environ.get('ADAPTER', 'DEFAULT')

# download
FEED_DOWNLOAD_TIMEOUT = 300  # seconds

# query selectors
TYPE_CHECK_LEVEL = 1  # [0, 1, 2], 0: skip, 1: logger warning, 2: strictly raise TypeError on type mismatch
