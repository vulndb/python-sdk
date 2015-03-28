Python SDK to access the `vulnerability database <https://github.com/vulndb/data)>`_

Build status:

.. image:: https://circleci.com/gh/vulndb/python-sdk/tree/master.svg?style=svg
   :alt: Build Status
   :align: right
   :target: https://circleci.com/gh/vulndb/python-sdk/tree/master

Installation
============

::

    git clone https://github.com/vulndb/python-sdk.git
    python setup.py install

Usage
=====

::

    >>> from vulndb import DBVuln
    >>> dbv = DBVuln.from_id(42)
    >>> dbv.get_title()
    'SQL Injection'
    >>> dbv.get_severity()
    'High'
    >>> r = dbv.get_references()[0]
    >>> r.get_url()
    'http://example.com/sqli-description.html'
    >>> r.get_title()
    'SQL injection cheat-sheet'


More methods and helpers available in the source code.

Contributing
============
Send your `pull requests <https://help.github.com/articles/using-pull-requests/`_
with improvements and bug fixes, making sure that all tests ``PASS``:

::

    $ nosetests vulndb/
    ..........
    ----------------------------------------------------------------------
    Ran 10 tests in 0.355s

    OK


Install the test dependencies by running ``pip install -r vulndb/requirements-dev.txt``
