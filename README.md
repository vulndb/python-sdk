Python SDK to access the [vulnerability database](https://github.com/vulndb/data)

## Installation
```bash
git clone https://github.com/vulndb/python-sdk.git
python setup.py install
```

## Usage

```python
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
```

More methods and helpers available in the source code.

## Contributing
Send your [pull requests](https://help.github.com/articles/using-pull-requests/)
with improvements and bug fixes, making sure that all tests `PASS`:

```console
$ nosetests vulndb/
......
----------------------------------------------------------------------
Ran 6 test in 0.535s

OK
```

Install the test dependencies by running `pip install -r vulndb/requirements-dev.txt`
