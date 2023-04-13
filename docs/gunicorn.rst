Running a Data Provider with gunicorn
=====================================

.. note::

    Functionality added in v0.2.4, this should be used in preference to the local SSL dev version described elsewhere
    where possible, it's reasonably easy to run quickly and also suited for more production-grade use.

.. warning::

    This should be deployed behind a proxy such as Nginx, there are instructions on how to deploy in a production
    environment in `the gunicorn docs <https://docs.gunicorn.org/en/stable/deploy.html>`_

`gunicorn <https://gunicorn.org/>`_ is a lightweight Python WSGI HTTP server for linux and other Unix-like operating
systems. This module includes support for running a |FAPI| compliant `Data Provider` within gunicorn, through the
`ClientAuthApplication` custom application class.

.. literalinclude:: ../../examples/gunicorn_provider.py
    :language: python

To use this, firstly add the `gunicorn_cert_parser` as an argument when creating the `AccessTokenValidator` object, then
run the application through the `ClientAuthApplication` ``run`` method. This will use gunicorn to run, as configured,
requiring client SSL certs and using ``certifi`` as the CA store.