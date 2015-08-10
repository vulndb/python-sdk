Python SDK to access the `vulnerability database <https://github.com/vulndb/data>`_

.. image:: https://circleci.com/gh/vulndb/python-sdk/tree/master.svg?style=svg
   :alt: Build Status
   :align: right
   :target: https://circleci.com/gh/vulndb/python-sdk/tree/master

Installation
============
It's possible to install `the latest stable release from pypi <https://pypi.python.org/pypi/vulndb>`_:

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
    u'Remote File Inclusion'
    >>> dbv.description
    u'Web applications occasionally use parameter values to store the location of a file which will later be required by the server.\n\nAn example of this is often seen in error pages, where the actual file path for the error page is stored in a parameter value -- for example `example.com/error.php?page=404.php`.\n\nA remote file inclusion occurs when the parameter value (ie. path to file being called by the server) can be substituted with the address of remote resource -- for example: `yoursite.com/error.asp?page=http://anothersite.com/somethingBad.php` In some cases, the server will process the fetched resource; therefore, if the resource contains server-side code matching that of the framework being used (ASP, PHP, JSP, etc.), it is probable that the resource will be executed as if it were part of the web application.\n\nThe tool discovered that it was possible to substitute a parameter value with an external resource and have the server fetch it and include its contents in the response.'
    >>> dbv.fix_guidance
    u'It is recommended that untrusted data is never used to form a file location to be included.\n\nTo validate data, the application should ensure that the supplied value for a file is permitted. This can be achieved by performing whitelisting on the parameter value, by matching it against a list of permitted files. If the supplied value does not match any value in the whitelist, then the server should redirect to a standard error page.\n\nIn some scenarios, where dynamic content is being requested, it may not be possible to perform validation against a list of trusted resources, therefore the list must also become dynamic (updated as the files change), or perform filtering to remove extraneous user input (such as semicolons, periods etc.) and only permit `a-z0-9`.\n\nIt is also advised that sensitive files are not stored within the web root and that the user permissions enforced by the directory are correct.'
    >>> dbv.severity
    u'high'
    >>> r = dbv.references[0]
    >>> r.url
    u'http://projects.webappsec.org/Remote-File-Inclusion'
    >>> r.title
    u'WASC'


More attributes, methods and helpers are well documented and available in the
`source code <https://github.com/vulndb/python-sdk/blob/master/vulndb/db_vuln.py>`_.

Contributing
============
Send your `pull requests <https://help.github.com/articles/using-pull-requests/>`_
with improvements and bug fixes, making sure that all tests ``PASS``:

::

    $ cd python-sdk
    $ virtualenv venv
    $ . venv/bin/activate
    $ pip install -r vulndb/requirements-dev.txt
    $ nosetests vulndb/
    ..........
    ----------------------------------------------------------------------
    Ran 10 tests in 0.355s

    OK


Updating the database
=====================
This package embeds the `vulnerability database <https://github.com/vulndb/data>`_
in the ``vulndb/db/`` directory. To update the database with new information
follow these steps:

::

    # Update the database
    tools/update-db.sh

After updating the database it's a good idea to publish the latest at ``pypi`` using:

::

    python setup.py sdist upload


