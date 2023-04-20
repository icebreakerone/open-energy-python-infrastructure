Metadata File Handling
======================

The `Metadata` class represents a single record in a metadata file published by a `data provider`. It can be loaded
from URL or file location through the `load_metadata` function.

The metadata file specification can be found `here <https://icebreakerone.github.io/open-energy-technical-docs/main/metadata.html>`_

.. note::

    Currently the code here only handles the ``content`` block, which it parses as a chunk of JSON-LD. It exposes this
    through a `JSONLDContainer` instance to simplify access to properties.

The `metadata.DC`, `metadata.DCAT` and `metadata.OE` values are the fully expanded namespace prefixes of the Dublin
Core, Data Catalogue, and Open Energy ontologies respectively.