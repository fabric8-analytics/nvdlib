"""NVD Feed data representation model."""
import datetime
import typing

from abc import ABC, abstractmethod
from collections import namedtuple


class Entry(object):
    """Representation of NVD Feed entry encapsulating other objects."""

    def __init__(self, data: dict):
        self._cve = CVE(data=data['cve'])
        self._configurations = Configurations(data=data['configurations'])
        self._impact = Impact(data=data['impact'])

        time_format = "%Y-%m-%dT%H:%MZ"
        self._published_date = datetime.datetime.strptime(
            data['publishedDate'],
            time_format
        )
        self._modified_date = datetime.datetime.strptime(
            data['lastModifiedDate'],
            time_format
        )

    @property
    def cve(self) -> "CVE":
        return self._cve

    @property
    def configurations(self) -> "Configurations":
        return self._configurations

    @property
    def impact(self) -> "Impact":
        return self._impact

    @property
    def published_date(self) -> datetime.datetime:
        return self._published_date

    @property
    def modified_date(self) -> datetime.datetime:
        return self._modified_date


class CVE(namedtuple('CVE', [
    'id_', 'assigner', 'data_version',
    'affects', 'references', 'descriptions'
])):
    """Representation of NVD CVE object."""

    def __new__(cls,
                id_: str = None,
                assigner: str = None,
                data_version: str = None,
                affects: 'AffectsNode' = None,
                references: 'ReferenceNode' = None,
                descriptions: 'DescriptionNode' = None):

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

        affects = AffectsNode(data['affects'])
        references = ReferenceNode(data['references'])
        descriptions = DescriptionNode(data['description'])

        return super(CVE, cls).__new__(
            cls,
            id_=id_,
            assigner=assigner,
            data_version=data_version,
            affects=affects,
            references=references,
            descriptions=descriptions)


class Node(ABC):

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
        return str(self._data)

    @property
    def data(self):
        return self._data

    @abstractmethod
    def parse(self, entry: typing.Any):
        """Parse the entry relevant to the current Node class."""


class DescriptionNode(Node):

    class Description(namedtuple('Description', ['lang', 'value'])):

        def __new__(cls, lang: str, value: str):
            return super().__new__(
                cls,
                lang=lang,
                value=value
            )

    def __init__(self, data: dict):
        description_data = data['description_data']

        super(DescriptionNode, self).__init__(*description_data)

    def parse(self, entry: typing.Dict[str, str]):
        return self.Description(**entry)


class ReferenceNode(Node):

    class Reference(namedtuple('Reference', ['url', 'name', 'refsource'])):

        def __new__(cls, url: str, name: str, refsource: str):
            return super().__new__(
                cls,
                url=url,
                name=name,
                refsource=refsource
            )

    def __init__(self, data: dict):
        reference_data = data['reference_data']

        super(ReferenceNode, self).__init__(*reference_data)

    def parse(self, entry: typing.Dict[str, str]):
        return self.Reference(**entry)


class AffectsNode(Node):

    class Product(namedtuple('Reference', ['name', 'vendor', 'versions'])):

        def __new__(cls, vendor_name: str, product_name: str, versions: list):
            return super().__new__(
                cls,
                name=product_name,
                vendor=vendor_name,
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

        super(AffectsNode, self).__init__(*affects_data)

    def parse(self, entry: typing.Dict[str, str]):
        return self.Product(*entry)


class Configurations(object):
    """Representation of NVD Configurations object."""

    def __init__(self, data: dict):
        pass


class Impact(object):
    """Representation of NVD Impact object."""

    def __init__(self, data: dict):
        pass
