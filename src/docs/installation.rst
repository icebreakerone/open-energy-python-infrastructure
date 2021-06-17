Installation
============

The library requires Python 3.8 or newer. Use of a `virtual environment <https://docs.python.org/3/tutorial/venv.html>`_
is strongly recommended.

Installing with pip
-------------------

.. code-block:: bash

    > pip3 install ib1.openenergy.support

Installing from source
----------------------

This will install the library in development mode - this means any changes you make to source files in your local git
repository will be immediately reflected in the contents of the library as used by other code. In other respects this
behaves identically to installing with either ``python3 setup.py install`` or by installing via ``pip`` as shown above.

.. code-block:: bash

    > git clone git@github.com:icebreakerone/open-energy-python-infrastructure.git
    > cd open-energy-python-infrastructure/src/python
    > python3 setup.py develop

Adding OE3 root certificates
----------------------------

The certificates used to mutually authenticate between data and service providers within |OE3| are signed by our
authorization server. In order to validate correctly, you need to add the root and intermediate signing certificates
to the ``certifi`` CA file used by Python (Python does not use the operating system CA store).

.. warning::

    You need to do this. If you do not do this, you will see SSL related errors in various places. It is not an optional
    step!

As of version ``0.2.3`` of this library, installing the library also adds a command which can do this automatically. First
activate any virtual environment, install the library as above, and run:

.. code-block:: bash

    > oe_install_cacerts

This will fetch the extra certificates needed from our github repository and append them to the set of CA certificates
used by the Python code here. It will not make any changes to the operating system trusted root certificates, any
changes are strictly local to your Python environment.

.. note::

    The command will check whether the certificates have already been added and will not produce duplicates, it's
    therefore safe to run this even if you believe you may have already done so.

If you need to reset your certifi installation, or if it is ever updated (it's good practice to check periodically for
changes to this library as this is the way root CAs are provided or invalidated for Python code) you will need to redo
the above command. For consistency, it's best to explicitly uninstall then reinstall the certifi library, that way you
know you're always starting from a clean, unmodified, CA file:

.. code-block:: bash

    > pip3 uninstall certifi
    > pip3 install certifi
    > oe_install_cacerts

Specifying alternate certificates
#################################

You can supply an optional ``url`` parameter to this tool to override the default location for the certificates to add
to your ``castore.pem`` file:

.. code-block::

    usage: oe_install_cacerts [-h] [-u URL]

    optional arguments:
      -h, --help         show this help message and exit
      -u URL, --url URL  URL of additional root certificates, defaults to certs from Open Energy github
