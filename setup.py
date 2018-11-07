import os
from pathlib import Path

from setuptools import setup, find_packages


BASE_DIR = os.path.dirname(__file__)

ABOUT = dict()
with open(Path(BASE_DIR) / 'nvdlib' / '__about__.py') as f:
    exec(f.read(), ABOUT)

with open('requirements.txt') as f:
    REQUIREMENTS = f.read().splitlines()

setup(
    name=ABOUT['__title__'],
    version=ABOUT['__version__'],

    author=ABOUT['__author__'],
    author_email=ABOUT['__email__'],
    url=ABOUT['__url__'],

    license=ABOUT['__license__'],

    description=ABOUT['__summary__'],
    long_description="The nvdlib library allows for easy fetching,"
                     " comfortable exploration and lightweight querying"
                     " of NVD Vulnerability Feeds. It achieves that by"
                     " providing simplistic database-like interface and custom"
                     " NVD, object-oriented, model.",

    classifiers=[
        "Development Status :: 2 - Pre-Alpha",
        "Topic :: Utilities",
        "Programming Language :: Python :: 3.6",
        "Programming Language :: Python :: 3.7",
        'License :: OSI Approved :: MIT License'
    ],

    keywords='cve mitre nvd json feed vulnerability',

    packages=find_packages(exclude=['tests', 'tests.*']),

    install_requires=REQUIREMENTS,
    tests_require=[
        'pytest',
    ]
)
