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
    DB_VERSION_FILE = 'db-version.txt'
    DEFAULT_LANG = 'en'

    def __init__(self, _id=None, title=None, description=None, severity=None,
                 wasc=None, tags=None, cwe=None, owasp_top_10=None,
                 fix_guidance=None, fix_effort=None, references=None,
                 db_file=None):
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
        self.fix_guidance = fix_guidance
        self.fix_effort = fix_effort
        self.references = references
        self.db_file = db_file

    @staticmethod
    def get_json_path(language=DEFAULT_LANG):
        """
        :param language: The user's language (en, es, etc.)
        :return: The path where the json files are located
        """
        return os.path.join(DBVuln.DB_PATH, language)

    @staticmethod
    def get_description_path(language=DEFAULT_LANG):
        """
        :param language: The user's language (en, es, etc.)
        :return: The path where the description markdown files are located
        """
        return os.path.join(DBVuln.DB_PATH, language, 'description')

    @staticmethod
    def get_fix_path(language=DEFAULT_LANG):
        """
        :param language: The user's language (en, es, etc.)
        :return: The path where the fix markdown files are located
        """
        return os.path.join(DBVuln.DB_PATH, language, 'fix')

    @staticmethod
    def get_all_languages():
        return os.listdir(DBVuln.DB_PATH)

    @staticmethod
    def get_db_version():
        db_version = os.path.join(os.path.dirname(os.path.realpath(__file__)),
                                  DBVuln.DB_VERSION_FILE)
        return file(db_version).read().strip()

    @classmethod
    def from_file(cls, db_file, language=DEFAULT_LANG):
        """
        This is an alternative "constructor" for the DBVuln class which loads
        the data from a file.

        :param db_file: Contents of a json file from the DB
        :param language: The user's language (en, es, etc.)
        """
        data = DBVuln.load_from_json(db_file, language=language)
        return cls(**data)

    @classmethod
    def from_id(cls, _id, language=DEFAULT_LANG):
        """
        This is an alternative "constructor" for the DBVuln class which searches
        the db directory to find the right file for the provided _id
        """
        db_file = DBVuln.get_file_for_id(_id, language=language)
        data = DBVuln.load_from_json(db_file, language=language)
        return cls(**data)

    def get_owasp_top_10_references(self):
        for owasp_version in self.owasp_top_10:
            for risk_id in self.owasp_top_10[owasp_version]:
                ref = self.get_owasp_top_10_url(owasp_version, risk_id)
                if ref is not None:
                    yield owasp_version, risk_id, ref

    @staticmethod
    def get_file_for_id(_id, language=DEFAULT_LANG):
        """
        Given _id, search the DB for the file which contains the data

        :param _id: The id to search (int)
        :param language: The user's language (en, es, etc.)
        :return: The filename
        """
        file_start = '%s-' % _id

        json_path = DBVuln.get_json_path(language=language)

        for _file in os.listdir(json_path):
            if _file.startswith(file_start):
                return os.path.join(json_path, _file)

        raise NotFoundException('No data for ID %s' % _id)

    @staticmethod
    def get_all_db_ids(language=DEFAULT_LANG):
        """
        :return: A list with all the database IDs as integers
        """
        _ids = []
        json_path = DBVuln.get_json_path(language=language)

        for _file in os.listdir(json_path):

            if not _file.endswith('.json'):
                continue

            _id = _file.split('-')[0]
            _ids.append(_id)

        return _ids

    @staticmethod
    def handle_ref(attr, language=DEFAULT_LANG):
        """
        Receives something like:

           {
             "$ref": "#/files/description/1"
           },

        Or:

           {
             "$ref": "#/files/fix/39"
           }

        And returns the contents of the description or fix file.

        :param attr: A dict containing a reference
        :param language: The user's language (en, es, etc.)
        :return: Markdown referenced by the attr
        """
        ref = attr.get('$ref', None)
        if ref is None:
            raise NotFoundException('No $ref in attribute')

        _, files, _type, _id = ref.split('/')

        if 'files' != files:
            raise NotFoundException('Mandatory "files" path was not found in $ref')

        if _type not in ('fix', 'description'):
            raise NotFoundException('Mandatory fix or description not found in $ref')

        if not _id.isdigit():
            raise NotFoundException('Mandatory integer ID not found in $ref')

        file_path = os.path.join(DBVuln.get_json_path(language=language),
                                 _type,
                                 '%s.md' % _id)

        if not os.path.exists(file_path):
            raise NotFoundException('$ref points to a non existing file')

        return file(file_path).read()

    @staticmethod
    def load_from_json(db_file, language=DEFAULT_LANG):
        """
        Parses the JSON data and returns it

        :param db_file: File and path pointing to the JSON file to parse
        :param language: The user's language (en, es, etc.)
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
            'description': DBVuln.handle_ref(raw['description'], language=language),
            'severity': raw['severity'],
            'wasc': raw.get('wasc', []),
            'tags': raw.get('tags', []),
            'cwe': raw.get('cwe', []),
            'owasp_top_10': raw.get('owasp_top_10', {}),
            'fix_effort': raw['fix']['effort'],
            'fix_guidance': DBVuln.handle_ref(raw['fix']['guidance'], language=language),
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
    def is_valid_id(_id, language=DEFAULT_LANG):
        try:
            DBVuln.get_file_for_id(_id, language=language)
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
                self.fix_effort == other.fix_effort and
                self.fix_guidance == other.fix_guidance and
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
