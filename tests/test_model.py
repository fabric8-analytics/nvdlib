"""Tests for nvdlib model."""

import datetime
import json
import unittest

from nvdlib import model


SAMPLE_CVE_PATH = 'data/cve-1.0-sample.json'

with open(SAMPLE_CVE_PATH) as f:
    DATA = json.loads(f.read())


class TestEntries(unittest.TestCase):
    """Test Entries subclasses."""

    def test_description_node(self):
        """Test DescriptionEntry class."""
        desc_entry = model.DescriptionEntry(DATA)

        self.assertIsInstance(desc_entry, model.DescriptionEntry)

        # test iteration and __getitem__
        desc_next = next(desc_entry)
        desc_get = desc_entry[0]

        for desc in [desc_next, desc_get]:
            self.assertTrue(desc)
            self.assertEqual(desc.lang, 'en')

        expected_iterations = 1
        for _ in desc_entry:
            expected_iterations -= 1

        self.assertEqual(expected_iterations, 0)

    def test_reference_entry(self):
        """Test ReferenceEntry class."""
        ref_entry = model.ReferenceEntry(DATA['cve']['references'])

        self.assertIsInstance(ref_entry, model.ReferenceEntry)

        # test iteration and __getitem__
        ref_next = next(ref_entry)
        ref_get = ref_entry[0]

        for ref in [ref_next, ref_get]:
            self.assertTrue(ref)
            self.assertIsInstance(ref.url, str)
            self.assertIsInstance(ref.name, str)
            self.assertIsInstance(ref.refsource, str)

        expected_iterations = 6
        for _ in ref_entry:
            expected_iterations -= 1

        self.assertEqual(expected_iterations, 0)

    def test_affects_entry(self):
        """Test AffectsEntry class."""
        affects_entry = model.AffectsEntry(DATA['cve']['affects'])

        self.assertIsInstance(affects_entry, model.AffectsEntry)

        # test iteration and __getitem__
        affects_next = next(affects_entry)
        affects_get = affects_entry[0]

        for product in [affects_next, affects_get]:
            self.assertTrue(product)
            self.assertIsInstance(product.product_name, str)
            self.assertIsInstance(product.vendor_name, str)
            self.assertIsInstance(product.versions, list)

        expected_iterations = 5
        for _ in affects_entry:
            expected_iterations -= 1

        self.assertEqual(expected_iterations, 0)


class TestConfigurations(unittest.TestCase):
    """Test CVE model."""

    def test___init__(self):
        """Test Configurations `__init__` method."""
        config = model.Configurations.from_data(DATA['configurations'])

        self.assertIsInstance(config, model.Configurations)

        # ---
        # test attributes
        attributes = [
            'cve_data_version', 'nodes'
        ]

        expected_return_types = [
            str,
            list
        ]

        for attr, type_ in zip(attributes, expected_return_types):
            self.assertIsInstance(getattr(config, attr), type_)

        # ---
        # test empty data
        config = model.Configurations.from_data(dict())

        self.assertIsInstance(config, model.Configurations)


class TestImpact(unittest.TestCase):
    """Test CVE model."""

    def test___init__(self):
        """Test Impact `__init__` method."""
        impact = model.Impact.from_data(DATA['impact'])

        self.assertIsInstance(impact, model.Impact)

        # ---
        # test attributes
        attributes = [
            'severity', 'exploitability_score', 'impact_score', 'cvss'
        ]

        expected_return_types = [
            str, float, float, model.Impact.CVSSNode
        ]

        for attr, type_ in zip(attributes, expected_return_types):
            self.assertIsInstance(getattr(impact, attr), type_)

        # ---
        # test empty data
        impact = model.Impact.from_data(dict())

        self.assertIsInstance(impact, model.Impact)


class TestCVE(unittest.TestCase):
    """Test CVE model."""

    def test___init__(self):
        """Test CVE `__init__` method."""
        cve = model.CVE.from_data(DATA)

        self.assertIsInstance(cve, model.CVE)

        # ---
        # test attributes
        attributes = [
            'id_', 'assigner', 'data_version',
            'affects', 'references', 'descriptions'
        ]

        expected_return_types = [
            str, str, str,
            model.AffectsEntry, model.ReferenceEntry, model.DescriptionEntry
        ]

        for attr, type_ in zip(attributes, expected_return_types):
            self.assertIsInstance(getattr(cve, attr), type_)


class TestDocument(unittest.TestCase):
    """Test Document model."""

    def test___init__(self):
        """Test Entry `__init__` method."""
        doc = model.Document.from_data(DATA)

        self.assertIsInstance(doc, model.Document)

        # ---
        # test attributes
        attributes = [
            'cve', 'configurations', 'impact',
            'published_date', 'modified_date'
        ]

        expected_return_types = [
            model.CVE, model.Configurations, model.Impact,
            datetime.datetime, datetime.datetime
        ]

        for attr, type_ in zip(attributes, expected_return_types):
            self.assertIsInstance(getattr(doc, attr), type_)


class TestCollection(unittest.TestCase):
    """Test Collection model."""

    def test___init__(self):
        document = model.Document.from_data(DATA)
        collection = model.Collection([document])

        self.assertIsInstance(collection, model.Collection)

        # collection should contain 1 document
        self.assertEqual(len(collection), 1)

    def test_select(self):
        pass

    def test_project(self):
        pass

    def test_filter(self):
        pass
