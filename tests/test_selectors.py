"""Tests for selector module."""

import json
import unittest

import nvdlib.query_selectors as selectors
from nvdlib import utils


SAMPLE_CVE_PATH = 'data/cve-1.0-sample.json'

with open(SAMPLE_CVE_PATH) as f:
    DATA = json.loads(f.read())


class TestSelector(unittest.TestCase):
    """Tests for Selector class."""

    def test_match(self):
        """Test `match` selector."""
        obj = utils.AttrDict(**{'A11': {'A21': 2}, 'A12': 1})

        # exact match
        select = selectors.match(pattern=1)
        # simple, exact match
        self.assertTrue(select(obj, 'A12'))

        # exact match
        select = selectors.match(pattern=2)
        self.assertFalse(select(obj, 'A12'))

        # ---
        # pattern
        select = selectors.match(pattern=r"(\d)+")

        self.assertTrue(select(obj, 'A12'))
        # nested
        self.assertTrue(select(obj, 'A11.A21'))

    def test_search(self):
        """Test `search` selector."""
        obj = utils.AttrDict(**{'A11': {'A21': 'abcdefgh'}, 'A12': 'abcd'})

        # exact search
        select = selectors.search(pattern='abcd')
        # simple, exact match
        self.assertTrue(select(obj, 'A12'))

        select = selectors.search(pattern='abc')
        self.assertTrue(select(obj, 'A12'))

        select = selectors.search(pattern='bca')
        self.assertFalse(select(obj, 'A12'))

        # ---
        # pattern
        select = selectors.search(pattern=r"(\w)+")

        self.assertTrue(select(obj, 'A12'))
        # nested
        self.assertTrue(select(obj, 'A11.A21'))

    def test_contains(self):
        """Test `contains` selector."""

    def test_in_range(self):
        """Test `in_range` selector."""

    def test_in_date_range(self):
        """Test `in_date_range` selector."""
