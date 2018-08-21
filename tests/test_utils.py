"""Tests for utils module.

This module is meant for simple utility testing, tests might not be provided
for all utils or contain asserts or true unit tests.

Utils module might be excluded from coverage measures.
"""

import unittest

from nvdlib import utils


class TestUtils(unittest.TestCase):

    def test_rhasattr(self):
        """Test utils.rhasattr function."""
        obj = utils.AttrDict(
            **{
                'foo': {
                    'bar': None
                }
            }
        )

        self.assertTrue(utils.rhasattr(obj, 'foo.bar'))
        self.assertTrue(utils.rhasattr(obj, 'foo'))

        obj_with_arrays = utils.AttrDict(
            **{
                'buzz': [
                    obj,
                    obj
                ]
            }
        )

        # ---
        # arrays

        self.assertTrue(utils.rhasattr(obj_with_arrays, 'buzz.foo'))
        self.assertTrue(utils.rhasattr(obj_with_arrays, 'buzz.foo.bar'))

    def test_rgetattr(self):
        """Test utils.rgetattr function."""

        obj = utils.AttrDict(
            **{
                'foo': {
                    'bar': True
                }
            }
        )

        self.assertIsInstance(utils.rgetattr(obj, 'foo'), utils.AttrDict)
        self.assertIsInstance(utils.rgetattr(obj, 'foo.bar'), bool)
        self.assertTrue(utils.rgetattr(obj, 'foo.bar'))
