Python API : ib1.openenergy.support
===================================

Python docs and source for this package

External APIs
-------------

.. automodule:: ib1.openenergy.support
    :members:

Metadata APIs
-------------

API to handle the metadata format described in `Data Set Metadata <https://icebreakerone.github.io/open-energy-technical-docs/main/metadata.html>`_

.. automodule:: ib1.openenergy.support.metadata
    :members:

Gunicorn support APIs
---------------------

Support for running data providers within the `Gunicorn <https://gunicorn.org/>`_ WSGI container

.. automodule:: ib1.openenergy.support.gunicorn
    :members:

SSL Development APIs
--------------------

.. warning::

    This is deprecated since 0.2.4, use the gunicorn support above instead.

.. automodule:: ib1.openenergy.support.flask_ssl_dev
    :members:

Internal APIs
-------------

.. note::

   The classes below are primarily used internally within Open Energy to manage information in our
   membership directory and CKAN servers, they are unlikely to be of interest to third parties implementing
   Data Provider or Consumer components.

.. automodule:: ib1.openenergy.support.raidiam
    :members:

.. automodule:: ib1.openenergy.support.ckan
    :members:

.. automodule:: ib1.openenergy.support.directory_tools
    :members:
