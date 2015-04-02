import os
import json

from vulndb.constants.wasc import WASC_ID_TO_URL
from vulndb.constants.cwe import CWE_URL_FMT
from vulndb.constants.owasp import (OWASP_TOP10_2010_URL_FMT,
                                    OWASP_TOP10_2013_URL_FMT)


class DBVuln(object):
    """
    Wrapper around a vulnerability as defined in vulndb JSON files.

    :see: https://github.com/vulndb/data/issues/5
    :see: https://github.com/vulndb/data
    """
    DB_PATH = os.path.join(os.path.dirname(os.path.realpath(__file__)), 'db')

    def __init__(self, _id=None, title=None, description=None, severity=None,
                 wasc=None, tags=None, cwe=None, owasp_top_10=None, fix=None,
                 references=None, db_file=None):
        """
        Creates a new DBVuln, setting the internal attributes to the provided
        kwargs.
        """
        self.id = _id
        self.title = title
        self.description = description
        self.severity = severity
        self.wasc = wasc
        self.tags = tags
        self.cwe = cwe
        self.owasp_top_10 = owasp_top_10
        self.fix = fix
        self.references = references
        self.db_file = db_file

    @classmethod
    def from_file(cls, db_file):
        """
        This is an alternative "constructor" for the DBVuln class which loads
        the data from a file.
        """
        data = DBVuln.load_from_json(db_file)
        return cls(**data)

    @classmethod
    def from_id(cls, _id):
        """
        This is an alternative "constructor" for the DBVuln class which searches
        the db directory to find the right file for the provided _id
        """
        db_file = DBVuln.get_file_for_id(_id)
        data = DBVuln.load_from_json(db_file)
        return cls(**data)

    def get_owasp_top_10_references(self):
        for owasp_version in self.owasp_top_10:
            for risk_id in self.owasp_top_10[owasp_version]:
                ref = self.get_owasp_top_10_url(owasp_version, risk_id)
                if ref is not None:
                    yield owasp_version, risk_id, ref

    @property
    def fix_guidance(self):
        """
        :return: The text associated with the fix guidance:

            "fix": {
                    "guidance": "A very long text explaining how to fix...",
                    "effort": 50
                    },
        """
        return self.handle_multiline_field(self.fix['guidance'])

    @property
    def fix_effort(self):
        """
        :return: The effort (in minutes) associated with the fix

            "fix": {
                    "guidance": "A very long text explaining how to fix...",
                    "effort": 50
                    },
        """
        return self.fix['effort']

    @staticmethod
    def get_file_for_id(_id):
        """
        Given _id, search the DB for the file which contains the data
        :param _id: The id to search (int)
        :return: The filename
        """
        file_start = '%s-' % _id

        for _file in os.listdir(DBVuln.DB_PATH):
            if _file.startswith(file_start):
                return os.path.join(DBVuln.DB_PATH, _file)

        raise NotFoundException('No data for ID %s' % _id)

    @staticmethod
    def get_all_db_ids():
        """
        :return: A list with all the database IDs as integers
        """
        _ids = []

        for _file in os.listdir(DBVuln.DB_PATH):
            _id = _file.split('-')[0]
            _ids.append(_id)

        return _ids

    @staticmethod
    def load_from_json(db_file):
        """
        Parses the JSON data and returns it

        :param db_file: File and path pointing to the JSON file to parse
        :raises: All kind of exceptions if the file doesn't exist or JSON is
                 invalid.
        :return: None
        """
        # There are a couple of things I don't do here, and are on purpose:
        #   - I want to fail if the file doesn't exist
        #   - I want to fail if the file doesn't contain valid JSON
        raw = json.loads(file(db_file).read())

        # Here I don't do any error handling either, I expect the JSON files to
        # be valid
        data = {
            '_id': raw['id'],
            'title': raw['title'],
            'description': DBVuln.handle_multiline_field(raw['description']),
            'severity': raw['severity'],
            'wasc': raw.get('wasc', []),
            'tags': raw.get('tags', []),
            'cwe': raw.get('cwe', []),
            'owasp_top_10': raw.get('owasp_top_10', {}),
            'fix': raw['fix'],
            'references': DBVuln.handle_references(raw.get('references', [])),
            'db_file': db_file,
        }

        return data

    @staticmethod
    def get_wasc_url(wasc_id):
        """
        :return: The URL associated with the wasc_id, usually the WASC ID is
                 received by the developer from self.wasc and he uses this
                 method to give the user a URL

                 None is returned if the URL can't be found
        """
        if wasc_id in WASC_ID_TO_URL:
            return WASC_ID_TO_URL[wasc_id]

    @staticmethod
    def get_cwe_url(cwe_id):
        """
        Similar to get_wasc_url() but for CWE
        """
        return CWE_URL_FMT % cwe_id

    @staticmethod
    def get_owasp_top_10_url(owasp_version, risk_id):
        """
        Similar to get_wasc_url() but for OWASP Top 10
        """
        owasp_version = int(owasp_version)

        # Just return one of them, 2013 release has priority over 2010
        if owasp_version == 2013:
            return OWASP_TOP10_2013_URL_FMT % risk_id

        if owasp_version == 2010:
            return OWASP_TOP10_2010_URL_FMT % risk_id

    @staticmethod
    def handle_multiline_field(field_data):
        """
        According to the spec there might be some fields which contain long
        descriptions, which might be strings or lists with strings. I translate
        the list of strings into a long string and return it.

        :see: https://github.com/vulndb/data/issues/5
        :param field_data: A string or a list
        :return: A string
        """
        if isinstance(field_data, basestring):
            return field_data

        return '\n'.join(field_data)

    @staticmethod
    def handle_references(json_references):
        """
        Create a list of reference objects that represent this part of the JSON
        data:

          "references": [
              {"url": "http://foo.com/xss", "title": "First reference to ..."},
              {"url": "http://asp.net/xss", "title": "How to fix ..."},
              {"url": "http://owasp.org/xss", "title": "OWASP desc for XSS"}
            ]

        :return: A list with Reference objects
        """
        reference_list = []
        for reference_dict in json_references:
            reference_list.append(Reference(reference_dict['url'],
                                            reference_dict['title']))

        return reference_list

    @staticmethod
    def is_valid_id(_id):
        try:
            DBVuln.get_file_for_id(_id)
        except NotFoundException:
            return False
        else:
            return True

    def __str__(self):
        return 'DBVulnerability for %s - %s' % (self.title, self.id)

    def __repr__(self):
        return '<DBVulnerability (title: "%s" | id: %s) >' % (self.title,
                                                              self.id)

    def __eq__(self, other):
        return (self.id == other.id and
                self.title == other.title and
                self.description == other.description and
                self.severity == other.severity and
                self.wasc == other.wasc and
                self.tags == other.tags and
                self.cwe == other.cwe and
                self.owasp_top_10 == other.owasp_top_10 and
                self.fix == other.fix and
                self.references == other.references)


class Reference(object):
    def __init__(self, url, title):
        self.url = url
        self.title = title

    def __str__(self):
        return '[%s](%s)' % (self.title, self.url)

    def __repr__(self):
        return '<Reference (%s|%s)>' % (self.title, self.url)

    def __eq__(self, other):
        return self.url == other.url and self.title == other.title


class NotFoundException(Exception):
    pass