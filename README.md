# nvdlib

Lightweight library for accessing and querying NVD Vulnerability Feeds at ease. 


<br>

The [nvdlib](https://github.com/fabric8-analytics/nvdlib) library allows for easy fetching, comfortable exploration and lightweight querying of [NVD](https://nvd.nist.gov/vuln/data-feeds#JSON_FEED) Vulnerability Feeds.
\
It achieves that by providing simplistic database-like interface and custom NVD, object-oriented, model.

<br>

# Installation

The default version can be easily installed by common installation approach:

`python3 setup.py install`

or via pip

`pip3 install .`
 
<br>

# Architecture

The default architecture of nvdlib is lightweight and does not require any further set up other than the `pip` or `python` install.

The architecture of the nvdlib, however, is designed such that additional adapters can be implemented to handle backend in a certain way, allowing for f.e. mongodb database backend (This is currently scheduled for future work), while maintaining user-facing interface.

For more in-depth information about the architecture, software design choices and how it can be extended, take a look at [docs/architecture](/docs/architecture.md) document.

<br>

# Usage

> For the demonstration of basic usage, we recommend to check out our [tutorial](/nvdlib/tutorials/tutorial.ipynb) which is provided as a Jupyter Notebook.


### Fetching NVD Feeds and creating Collection of Documents

1. We will fetch NVD Feeds from NVD database using [FeedManager](/nvdlib/manager.py).

    FeedManager is a context manager which takes control over asynchronous calls using event loop.

    This will store JSON feeds locally for future usage.
    NOTE: In this tutorial, we won't cover any JSONFeed related operations, as it is assumed that this is not the purpose of nvdlib. However, nvdlib is capable of handling raw JSONFeeds and their metadata in case user needed such level of control.


2. Create collection from those feeds

    Creating collection from feeds parses each feed to its Document(get familiar with our model) form and produces a Collection object.

    [Collection](/nvdlib/collection.py) is a user facade which acts as a proxy to set of documents and makes quering and operation on documents much easier.
    Collections can use different adapters based on user choice.

    The default adapter despite being very lightweight, provides limited functionality and shows lower performence.


```python
FEED_NAMES = [2002, 2003, 2004, 2005]  # choose whichever feeds you want to fetch

with FeedManager(data_dir=tmp_dir, n_workers=5) as feed_manager:
    
    feeds = feed_manager.fetch_feeds(FEED_NAMES)
    collection = feed_manager.collect(feeds)  # create collection, optionaly, custom feeds can be specified 
    
    # [OPTIONAL] step
    collection.set_name('Tutorial')  # choose whatever name you want for future identification
```

<br>


### Getting familiar with NVD Document model

> NOTE: The model might change in the future by adding new attributes based on user feedback. The changes should not alter the model such that any attributes are removed, however.

It is important to get familiar with the document model. Although it is similar to the [NVD JSON Feed schema](https://csrc.nist.gov/schema/nvd/feed/0.1/nvd_cve_feed_json_0.1_beta.schema), there are subtle differences to achieve easier access or some attributes might be left out. The model schema is defined in [docs/model.md](/docs/model.md).

Spend some time exploring the Document model. Despite acting somewhat similar to dict, each attribute should be accessible via 'dot notation', python attribute hints should also help with the task, hence a comfortable access and attribute exploration should be guaranteed.

Example:

```python
# let there be an instance of document
doc: Document
```
```python
doc.pretty()  # pretty print the document
```

```python
doc.cve.pretty()  # each attribute of the Document also has the `pretty` method
```


```python
# project attributes via `project` method
doc.project({'cve.descriptions.data.value': 1})  # Note that even elements inside array can be accessed!
```

```python
# project attributes via `project` method and hide the document 'id_'
doc.project({'id_': 0, 'cve.descriptions.data.value': 1})  # Note that even elements inside array can be accessed!
```

<br>

### Iterating over collection of documents using Cursor
```python
# let there be a collection
collection: Collection
```

```python
cursor = collection.cursor()  # create cursor
```

```python
doc: Document = cursor.next()  # return next document
doc
```

```python
batch: list = cursor.next_batch()  # return next batch of documents
batch
```

<br>

### Querying collection of documents using query selectors

Currently, there are the following query selectors implemented (defined in [query_selectors.py module](/nvdlib/query_selectors.py)):

| selector | operation |
| - | - |
| `match` | perform regex match operation |
| `search` | perform regex search operation |
| `in_range` | return whether element value lies within given range |
| `in_` | return whether element is contained in an array |
| `gt` | compare two values using greater than operator |
| `ge` | compare two values using greater or equal than operator |
| `lt` | compare two values using lower than operator |
| `le` | compare two values using lower or equal than operator |

<br>

```python
# again, let there be a collection
collection: Collection
```

<br>

1. Querying by exact match

> Note: This query implicitly uses the `match` selector

```python
usoft_collection: Collection = collection.find({'cve.affects.data.vendor_name': 'microsoft'})  # returns new Collection
usof_colleciton.set_name('Microsoft collecion')  # optional step for user comfort
usof_collection
```

> Notice that we actually accessed `vendor_name` attribute of each element in `data` array using simple dot notation

```python
# draw sample from the microsoft collection
sample, = usoft_colleciton.sample(1)
sample.pretty()
```

<br>

2. Querying by pattern matches

```python
win_collection = collection.find({'cve.affects.data.product_name': search('windows')})
win_collection.set_name('Windows collection')  # optional step for user comfort
win_collection
```


```python
collection.find({'cve.year': match("200[1-3]{1}")})  # regex match
```

<br>

3. Querying by range of values

The query above using regex although possible, is not very intuitive. For this purpose, we provide methods in_ and in_range


```python
collection.find({'cve.year': in_range(2001, 2003)})
```


In this context (as years are always integer values), same query can be expressed by _in selector

```python
collection.find({'cve.year': in_([2001, 2002, 2003])})
```


4. Querying by value comparisons


```python
collection.find({'impact.cvss.base_score': gt(9)})
```


5. Complex queries

```python
# find pre-release cves published in december of any year with cvss score greater than 9
pre_release_december_collection = collection.find({
    'published_date.month': 12,
    'impact.cvss.base_score': ge(9.0),
    'cve.affects.data.versions': le('1.0.0')
})
pre_release_december_collection.set_name('December pre-release')
pre_release_december_collection
```

```python
# yet again, print sample
sample = pre_release_december_collection.pretty(sample_size=1)
sample.pretty()
```


<br>

# Notes & Issues:

- In order to use [nvdlib](https://github.com/fabric8-analytics/nvdlib) in Jupyter Notebook, `tornado==4.3.0` has to be used in order for `asyncio` to run properly. This is *not* an issue on the side of nvdlib and it is being work on (see https://github.com/jupyter/notebook/issues/3397). As this issue appears specificaly in Jupyter Notebook, and `tornado` is an indirect requirement, we suggest to create virtual environment with this `tornado` version for this purpose..


<br>
<br>

> Author: Marek Cermak <macermak@redhat.com>
\
Collaborators: Michal Srb <msrb@redhat.com>
