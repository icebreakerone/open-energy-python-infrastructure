Python API : icebreakerone.trust
===================================

Python docs and source for this package

External APIs
-------------

.. automodule:: icebreakerone.trust
    :members:

Metadata APIs
-------------

API to handle the metadata format described in `Data Set Metadata <https://icebreakerone.github.io/open-energy-technical-docs/main/metadata.html>`_

.. automodule:: icebreakerone.trust.metadata
    :members:

Gunicorn support APIs
---------------------

Support for running data providers within the `Gunicorn <https://gunicorn.org/>`_ WSGI container

.. automodule:: icebreakerone.trust.gunicorn
    :members:

SSL Development APIs
--------------------

.. warning::

    This is deprecated since 0.2.4, use the gunicorn support above instead.

.. automodule:: icebreakerone.trust.flask_ssl_dev
    :members:

Internal APIs
-------------

.. note::

   The classes below are primarily used internally within Open Energy to manage information in our
   membership directory and CKAN servers, they are unlikely to be of interest to third parties implementing
   Data Provider or Consumer components.

.. automodule:: icebreakerone.trust.raidiam
    :members:

.. automodule:: icebreakerone.trust.ckan
    :members:

.. automodule:: icebreakerone.trust.directory_tools
    :members:
