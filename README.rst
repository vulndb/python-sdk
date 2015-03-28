Python SDK to access the `vulnerability database <https://github.com/vulndb/data>`_

.. image:: https://circleci.com/gh/vulndb/python-sdk/tree/master.svg?style=svg
   :alt: Build Status
   :align: right
   :target: https://circleci.com/gh/vulndb/python-sdk/tree/master

Installation
============
It's possible to install the latest stable release from pypi:

::

    pip install vulndb


Or if you're interested in the latest version from our repository:

::

    git clone https://github.com/vulndb/python-sdk.git
    python setup.py install

Usage
=====

::

    >>> from vulndb import DBVuln
    >>> dbv = DBVuln.from_id(42)
    >>> dbv.title
    'SQL Injection'
    >>> dbv.severity
    'high'
    >>> r = dbv.references[0]
    >>> r.url
    'http://example.com/sqli-description.html'
    >>> r.title
    'SQL injection cheat-sheet'


More attributes, methods and helpers are well documented and available in the
`source code <https://github.com/vulndb/python-sdk/blob/master/vulndb/db_vuln.py>`_.

Updating the database
=====================
This package embeds the `vulnerability database <https://github.com/vulndb/data>`_
in the ``vulndb/db/`` directory. To update the database with new information
follow these steps:

::

    git clone https://github.com/vulndb/data.git
    cp -rf data/db/*.json vulndb/db/
    git commit vulndb/db/ -m 'Updated vulnerability database'
    bumpversion vulndb/version.txt --new-version 0.0.3
    git push

After updating the database it's a good idea to publish the latest at pypi using:

::

    python setup.py sdist upload


Contributing
============
Send your `pull requests <https://help.github.com/articles/using-pull-requests/>`_
with improvements and bug fixes, making sure that all tests ``PASS``:

::

    $ nosetests vulndb/
    ..........
    ----------------------------------------------------------------------
    Ran 10 tests in 0.355s

    OK


Install the test dependencies by running ``pip install -r vulndb/requirements-dev.txt``
