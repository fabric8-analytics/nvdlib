"""Tests for selector module."""

import json
import unittest

from datetime import datetime

import nvdlib.query_selectors as selectors
from nvdlib import utils


SAMPLE_CVE_PATH = 'data/cve-1.0-sample.json'

with open(SAMPLE_CVE_PATH) as f:
    DATA = json.loads(f.read())


class TestSelector(unittest.TestCase):
    """Tests for Selector class."""

    def test_match(self):
        """Test `match` selector."""
        obj = utils.AttrDict(**{'foo': {'bar': 2}, 'buzz': 1})

        # exact match
        select = selectors.match(pattern=1)
        # simple, exact match
        self.assertTrue(select(obj, 'buzz'))

        # exact match
        select = selectors.match(pattern=2)
        self.assertFalse(select(obj, 'buzz'))

        # ---
        # pattern
        select = selectors.match(pattern=r"(\d)+")

        self.assertTrue(select(obj, 'buzz'))
        # nested
        self.assertTrue(select(obj, 'foo.bar'))

    def test_search(self):
        """Test `search` selector."""
        obj = utils.AttrDict(
            **{'foo': {'bar': 'abcdefgh'}, 'buzz': 'abcd'}
        )

        # exact search
        select = selectors.search(pattern='abcd')
        # simple, exact match
        self.assertTrue(select(obj, 'buzz'))

        select = selectors.search(pattern='abc')
        self.assertTrue(select(obj, 'buzz'))

        select = selectors.search(pattern='bca')
        self.assertFalse(select(obj, 'buzz'))

        # ---
        # pattern
        select = selectors.search(pattern=r"(\w)+")

        self.assertTrue(select(obj, 'buzz'))
        # nested
        self.assertTrue(select(obj, 'foo.bar'))

        # ---
        # arrays
        obj_with_array = utils.AttrDict(
            **{
                'fuzz': [obj, obj]
            }
        )

        select = selectors.search(pattern=r"abc")

        # nested
        self.assertTrue(select(obj_with_array, 'fuzz.foo.bar'))
        self.assertTrue(select(obj_with_array, 'fuzz.buzz'))

        # incorrect, should not raise
        self.assertFalse(select(obj_with_array, 'fuzz.bar'))

    def test_greater(self):
        """Test `gt` and `ge` selector."""
        obj = utils.AttrDict(
            **{
                'foo': {'bar': 5},
                'time': datetime.now()
            }
        )
        select = selectors.gt(0)

        self.assertTrue(select(obj, 'foo.bar'))
        self.assertTrue(select(obj, 'time'))

        select = selectors.gt(5)
        self.assertFalse(select(obj, 'foo.bar'))

        select = selectors.gt(datetime.now())

        self.assertFalse(select(obj, 'time'))

        select = selectors.ge(5)
        self.assertTrue(select(obj, 'foo.bar'))

    def test_lower(self):
        """Test `lt` and `le` selector."""
        obj = utils.AttrDict(
            **{
                'foo': {'bar': 5},
                'time': datetime.now(),
                'arr': [
                    '1.0.0',
                    '1.4.3'
                ]
            }
        )
        select = selectors.lt(0)

        self.assertFalse(select(obj, 'foo.bar'))

        select = selectors.lt(10)
        self.assertTrue(select(obj, 'foo.bar'))

        select = selectors.lt(datetime.now())

        self.assertTrue(select(obj, 'time'))

        select = selectors.le(5)
        self.assertTrue(select(obj, 'foo.bar'))

        # ---
        # strings
        select = selectors.le('1.0.0')
        self.assertTrue(select(obj, 'arr'))

        select = selectors.lt('1.0.0')
        self.assertFalse(select(obj, 'arr'))

        select = selectors.lt('2.0.0')
        self.assertTrue(select(obj, 'arr'))

    def test_in_(self):
        """Test `in_` selector."""
        obj = utils.AttrDict(
            **{
                'foo': {'bar': 5},
                'buzz': False,
            }
        )

        select = selectors.in_([0, 5, 10, 15])
        self.assertTrue(select(obj, 'foo.bar'))

        select = selectors.in_([True, False])
        self.assertTrue(select(obj, 'buzz'))

    def test_in_range(self):
        """Test `in_range` selector."""
        obj = utils.AttrDict(
            **{'foo': {'bar': 5},
               'time': datetime.now()}
        )

        # wrong
        with self.assertRaises(ValueError):
            select = selectors.in_range(high=10, low=100)
            select(obj, 'foo.bar')

        select = selectors.in_range(high=10, low=0)
        self.assertTrue(select(obj, 'foo.bar'))

        select = selectors.in_range(high=10, low=5)
        self.assertTrue(select(obj, 'foo.bar'))

        select = selectors.in_range(high=5, low=0)
        self.assertTrue(select(obj, 'foo.bar'))

        select = selectors.in_range(high=4, low=0)
        self.assertFalse(select(obj, 'foo.bar'))

        select = selectors.in_range(high=datetime.now(), low=datetime(1, 1, 1))
        self.assertTrue(select(obj, 'time'))

        select = selectors.in_range(high=datetime(2, 2, 2), low=datetime(1, 1, 1))
        self.assertFalse(select(obj, 'time'))
