import datetime
import json
import unittest

from nvdlib import model


SAMPLE_CVE_PATH = 'data/cve-1.0-sample.json'


class TestEntry(unittest.TestCase):
    """Test Entry model."""

    def test___init__(self):
        """Test Entry `__init__` method."""
        with open(SAMPLE_CVE_PATH) as f:
            data = json.loads(f.read())
        entry = model.Entry(data)

        self.assertIsInstance(entry, model.Entry)

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
            self.assertIsInstance(getattr(entry, attr), type_)


class TestCVE(unittest.TestCase):
    """Test CVE model."""

    def test___init__(self):
        """Test CVE `__init__` method."""

        with open(SAMPLE_CVE_PATH) as f:
            data = json.loads(f.read())
            data = data['cve']

        cve = model.CVE.from_data(data)

        self.assertIsInstance(cve, model.CVE)

        # ---
        # test attributes
        attributes = [
            'id_', 'assigner', 'data_version',
            'affects', 'references', 'descriptions'
        ]

        expected_return_types = [
            str, str, str,
            model.AffectsNode, model.ReferenceNode, model.DescriptionNode
        ]

        for attr, type_ in zip(attributes, expected_return_types):
            self.assertIsInstance(getattr(cve, attr), type_)


class TestNodes(unittest.TestCase):
    """Test Node subclasses."""

    def test_description_node(self):
        """Test DescriptionNode class."""

        with open(SAMPLE_CVE_PATH) as f:
            data = json.loads(f.read())
            data = data['cve']['description']

        desc_node = model.DescriptionNode(data)

        self.assertIsInstance(desc_node, model.DescriptionNode)

        # test iteration and __getitem__
        desc_next = next(desc_node)
        desc_get = desc_node[0]

        for desc in [desc_next, desc_get]:
            self.assertTrue(desc)
            self.assertEqual(desc.lang, 'en')

        expected_iterations = 1
        for _ in desc_node:
            expected_iterations -= 1

        self.assertEqual(expected_iterations, 0)

    def test_reference_node(self):
        """Test ReferenceNode class."""

        with open(SAMPLE_CVE_PATH) as f:
            data = json.loads(f.read())
            data = data['cve']['references']

        ref_node = model.ReferenceNode(data)

        self.assertIsInstance(ref_node, model.ReferenceNode)

        # test iteration and __getitem__
        ref_next = next(ref_node)
        ref_get = ref_node[0]

        for ref in [ref_next, ref_get]:
            self.assertTrue(ref)
            self.assertIsInstance(ref.url, str)
            self.assertIsInstance(ref.name, str)
            self.assertIsInstance(ref.refsource, str)

        expected_iterations = 6
        for _ in ref_node:
            expected_iterations -= 1

        self.assertEqual(expected_iterations, 0)

    def test_affects_node(self):
        """Test AffectsNode class."""

        with open(SAMPLE_CVE_PATH) as f:
            data = json.loads(f.read())
            data = data['cve']['affects']

        affects_node = model.AffectsNode(data)

        self.assertIsInstance(affects_node, model.AffectsNode)

        # test iteration and __getitem__
        affects_next = next(affects_node)
        affects_get = affects_node[0]

        for product in [affects_next, affects_get]:
            self.assertTrue(product)
            self.assertIsInstance(product.name, str)
            self.assertIsInstance(product.vendor, str)
            self.assertIsInstance(product.versions, list)

        expected_iterations = 5
        for _ in affects_node:
            expected_iterations -= 1

        self.assertEqual(expected_iterations, 0)


class TestConfigurations(unittest.TestCase):
    """Test CVE model."""

    def test___init__(self):
        """Test Configurations `__init__` method."""

        with open(SAMPLE_CVE_PATH) as f:
            data = json.loads(f.read())
            data = data['configurations']

        config = model.Configurations(data)

        self.assertIsInstance(config, model.Configurations)


class TestImpact(unittest.TestCase):
    """Test CVE model."""

    def test___init__(self):
        """Test Impact `__init__` method."""

        with open(SAMPLE_CVE_PATH) as f:
            data = json.loads(f.read())
            data = data['impact']

        impact = model.Impact(data)

        self.assertIsInstance(impact, model.Impact)
