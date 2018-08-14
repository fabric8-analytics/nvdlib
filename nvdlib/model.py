"""NVD Feed data representation model.

Model:

    nvdlib.model.Document(
        cve: nvdlib.model.CVE(
             id_: str,
             assigner: str,
             data_version: str,
             affects: AffectsEntry(data: List[
                ProductNode(
                    vendor_name: str,
                    product_name: str,
                    versions: List[str])]
                )],
             references: ReferenceEntry(data: List[
                ReferenceNode(
                    url: str,
                    refsource: str
                )],
             descriptions: DescriptionEntry(data: List[
                DescriptionNode(
                    lang: str
                )]
        ),
        configurations: nvdlib.model.Configurations(
            cve_data_version: str,
            nodes: List[
                ConfigurationsEntry(
                    data: List[
                        ConfigurationsNode(
                            vulnerable: True,
                            cpe: str
                        )],
                    operator: str
            )]
        ),
        impact: nvdlib.model.Impact(
            severity: str,
            exploitability_score: float,
            impact_score: float,
            cvss: nvdlib.model.Impact.CVSSNode(
                version: str,
                access_vector: str,
                access_complexity: str,
                authentication: str,
                confidentiality_impact: str,
                integrity_impact: str,
                availability_impact: str,
                base_score: float
            )
        ),
        published_date: datetime.datetime(
            year: int,
            month: int,
            day: int,
            hour: int,
            minute: int
        ),
        modified_date: datetime.datetime(
            year: int,
            month: int,
            day: int,
            hour: int,
            minute: int
        )
    )

"""

import os
import datetime
import shutil
import tempfile
import typing

from abc import ABC, abstractmethod
from collections import namedtuple

from nvdlib import adapters, config
from nvdlib.selector import Selector


class Entry(ABC):

    def __init__(self, *data):
        self._data = [
            self.parse(entry) for entry in data
        ]
        self._state = 0

    def __iter__(self):
        self._state = 0

        return self

    def __next__(self):
        try:
            result = self._data[self._state]
        except IndexError:
            raise StopIteration

        self._state += 1

        return result

    def __getitem__(self, item: int):
        return self._data[item]

    def __len__(self):
        return len(self._data)

    def __str__(self):
        return f"{self.__class__.__name__}(data={str(self._data)}"

    def __repr__(self):
        return f"{self.__class__.__name__}(data={str(self._data)}"

    @property
    def data(self):
        return self._data

    @abstractmethod
    def parse(self, entry: typing.Any):
        """Parse the entry relevant to the current Node class."""


class DescriptionEntry(Entry):

    class DescriptionNode(namedtuple('DescriptionNode', ['lang', 'value'])):

        # noinspection PyInitNewSignature
        def __new__(cls, lang: str = None, value: str = None):
            return super().__new__(
                cls,
                lang=lang,
                value=value
            )

    def __init__(self, data: dict):
        description_data = data['description_data']

        super(DescriptionEntry, self).__init__(*description_data)

    def parse(self, entry: typing.Any):
        return self.DescriptionNode(**entry)


class ReferenceEntry(Entry):

    class ReferenceNode(namedtuple('Reference', ['url', 'name', 'refsource'])):

        # noinspection PyInitNewSignature
        def __new__(cls, url: str = None, name: str = None, refsource: str = None):
            return super().__new__(
                cls,
                url=url,
                name=name,
                refsource=refsource
            )

    def __init__(self, data: dict):
        reference_data = data['reference_data']

        super(ReferenceEntry, self).__init__(*reference_data)

    def parse(self, entry: typing.Any):
        return self.ReferenceNode(**entry)


class AffectsEntry(Entry):

    class ProductNode(namedtuple('ProductNode', ['vendor_name', 'product_name', 'versions'])):

        # noinspection PyInitNewSignature
        def __new__(cls,
                    vendor_name: str = None,
                    product_name: str = None,
                    versions: list = None):
            return super().__new__(
                cls,
                vendor_name=vendor_name,
                product_name=product_name,
                versions=versions
            )

    def __init__(self, data: dict):
        vendor_data = data['vendor']['vendor_data']

        affects_data = list()

        for vendor in vendor_data:
            vendor_name = vendor['vendor_name']
            product_data = vendor['product']['product_data']

            for product in product_data:
                product_name = product['product_name']
                version_data = [
                    v['version_value']
                    for v in product['version']['version_data']
                ]

                affects_data.append(
                    (product_name, vendor_name, version_data)
                )

        super(AffectsEntry, self).__init__(*affects_data)

    def parse(self, entry: typing.Any):
        return self.ProductNode(*entry)


class ConfigurationsEntry(Entry):

    class ConfigurationsNode(namedtuple('ConfigurationsNode', ['vulnerable', 'cpe'])):

        # noinspection PyInitNewSignature
        def __new__(cls, vulnerable: bool = None, cpe: str = None):
            return super().__new__(
                cls,
                vulnerable=vulnerable,
                cpe=cpe
            )

    def __init__(self, data: dict):
        self._operator: str = data['operator']

        super(ConfigurationsEntry, self).__init__(*data['cpe'])

    @property
    def operator(self) -> str:
        return self.operator

    def parse(self, entry: typing.Any):
        return self.ConfigurationsNode(entry['vulnerable'], entry['cpe23Uri'])


class Configurations(namedtuple('Configurations', [
    'cve_data_version', 'nodes'
])):
    """Representation of NVD Configurations object."""

    # noinspection PyInitNewSignature
    def __new__(cls,
                cve_data_version: str = None,
                nodes: typing.List[ConfigurationsEntry] = None):

        return super(Configurations, cls).__new__(
            cls,
            cve_data_version=cve_data_version,
            nodes=nodes,
        )

    @classmethod
    def from_data(cls, data):
        if not data:
            return cls(**{})

        return cls(
            cve_data_version=data['CVE_data_version'],
            nodes=[
                ConfigurationsEntry(node) for node in data['nodes']
            ]
        )


class Impact(namedtuple('Impact', [
    'severity', 'exploitability_score', 'impact_score', 'cvss'
])):
    """Representation of NVD Configurations object."""

    class CVSSNode(namedtuple('CVSSNode', [
        'version', 'access_vector', 'access_complexity', 'authentication',
        'confidentiality_impact', 'integrity_impact', 'availability_impact',
        'base_score'
    ])):

        def __new__(cls,
                    version: str = None,
                    access_vector: str = None,
                    access_complexity: str = None,
                    confidentiality_impact: str = None,
                    authentication: str = None,
                    integrity_impact: str = None,
                    availability_impact: str = None,
                    base_score: float = None):
            return super().__new__(
                cls,
                version=version,
                access_vector=access_vector,
                access_complexity=access_complexity,
                confidentiality_impact=confidentiality_impact,
                authentication=authentication,
                integrity_impact=integrity_impact,
                availability_impact=availability_impact,
                base_score=base_score,
            )

    # noinspection PyInitNewSignature
    def __new__(cls,
                severity: str = None,
                exploitability_score: float = None,
                impact_score: float = None,
                cvss: CVSSNode = None):
        return super(Impact, cls).__new__(
            cls,
            severity=severity,
            exploitability_score=exploitability_score,
            impact_score=impact_score,
            cvss=cvss
        )

    @classmethod
    def from_data(cls, data: dict):
        if not data:
            return cls(**{})

        impact_data = data['baseMetricV2']

        severity = impact_data['severity']
        exploitability_score = impact_data['exploitabilityScore']
        impact_score = impact_data['impactScore']

        cvss: dict = impact_data['cvssV2']
        cvss_modified = dict(
            version=cvss['version'],
            access_vector=cvss['accessVector'],
            access_complexity=cvss['accessComplexity'],
            confidentiality_impact=cvss['confidentialityImpact'],
            authentication=cvss['authentication'],
            integrity_impact=cvss['integrityImpact'],
            availability_impact=cvss['availabilityImpact'],
            base_score=cvss['baseScore'],
        )

        return cls(
            severity=severity,
            exploitability_score=exploitability_score,
            impact_score=impact_score,
            cvss=cls.CVSSNode(**cvss_modified)
        )


class CVE(namedtuple('CVE', [
    'id_', 'assigner', 'data_version',
    'affects', 'references', 'descriptions'
])):
    """Representation of NVD CVE object."""

    def __new__(cls,
                id_: str = None,
                assigner: str = None,
                data_version: str = None,
                affects: AffectsEntry = None,
                references: ReferenceEntry = None,
                descriptions: DescriptionEntry = None):

        return super(CVE, cls).__new__(
            cls,
            id_=id_,
            assigner=assigner,
            data_version=data_version,
            affects=affects,
            references=references,
            descriptions=descriptions)

    @classmethod
    def from_data(cls, data):
        meta = data['CVE_data_meta']
        id_ = meta['ID']
        assigner = meta['ASSIGNER']

        data_version = data['data_version']

        affects = AffectsEntry(data['affects'])
        references = ReferenceEntry(data['references'])
        descriptions = DescriptionEntry(data['description'])

        return cls(
            id_=id_,
            assigner=assigner,
            data_version=data_version,
            affects=affects,
            references=references,
            descriptions=descriptions)


class Document(namedtuple('Document', [
    'cve', 'configurations', 'impact', 'published_date', 'modified_date'
])):
    """Representation of NVD Feed entry encapsulating other objects."""

    # noinspection PyInitNewSignature
    def __new__(cls,
                cve: CVE = None,
                configurations: Configurations = None,
                impact: Impact = None,
                published_date: datetime.datetime = None,
                modified_date: datetime.datetime = None):

        return super(Document, cls).__new__(
            cls,
            cve=cve,
            configurations=configurations,
            impact=impact,
            published_date=published_date,
            modified_date=modified_date
        )

    @classmethod
    def from_data(cls, data: dict):
        if not data:
            return cls(**{})

        cve = CVE.from_data(data=data['cve'])
        configurations = Configurations.from_data(data=data['configurations'])
        impact = Impact.from_data(data=data['impact'])

        time_format = "%Y-%m-%dT%H:%MZ"
        published_date = datetime.datetime.strptime(
            data['publishedDate'],
            time_format
        )
        modified_date = datetime.datetime.strptime(
            data['lastModifiedDate'],
            time_format
        )

        return cls(
            cve=cve,
            configurations=configurations,
            impact=impact,
            published_date=published_date,
            modified_date=modified_date
        )


class Collection(object):
    """Collection of Documents."""

    def __init__(self,
                 data_iterator: typing.Iterable[Document],
                 storage: str = None,
                 adapter: str = 'DEFAULT'
                 ):
        self._count: int = 0
        self._clear_storage = True

        if storage:
            self._clear_storage = False
            self._storage = storage

        else:
            self._storage = storage or os.path.join(
                tempfile.gettempdir(),
                f"nvdlib/.dump/{id(self)}"
            )

        # create directory
        os.makedirs(self._storage)

        # initialize adapter
        self._adapter: adapters.BaseAdapter = getattr(
            adapters,  # load adapter directly from module
            adapter.upper()
        )()

        self._adapter.connect(storage=self._storage)
        self._adapter.process(data_iterator)

        self._data = self._adapter.sample()
        self._count = self._adapter.count()

    def __del__(self):
        if self._clear_storage:
            shutil.rmtree(self._storage)

    def __len__(self):
        return self._count

    def __iter__(self):
        # initialize adapter iterator
        self._adapter.__iter__()

        return self

    def __next__(self):
        return self._adapter.next()

    @property
    def storage(self):
        return self._storage

    def select(self, *selectors: Selector, operator='AND'):
        self._adapter.select(*selectors, operator=operator)

        return self

    def project(self, *selectors: Selector):
        raise NotImplementedError

    def filter(self, fn: callable):
        raise NotImplementedError

    def next(self):
        return self._adapter.next()

    def next_batch(self, batch_size: int = 20):
        return self._adapter.next_batch(batch_size)
