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
    def __init__(self, db_file=None):
        """
        Creates a new DBVuln, optionally provide the database file which will
        be loaded to populate all the internal attributes.

        :param db_file: File and path pointing to the JSON file to parse
        """
        self.id = None
        self.title = None
        self.description = None
        self.severity = None
        self.wasc = None
        self.tags = None
        self.cwe = None
        self.owasp_top_10 = None
        self.fix = None
        self.references = None

        if db_file:
            self.load_from_json(db_file)

    def load_from_json(self, db_file):
        """
        Parses and loads the JSON data into the internal attributes

        :param db_file: File and path pointing to the JSON file to parse
        :raises: All kind of exceptions if the file doesn't exist or JSON is
                 invalid.
        :return: None
        """
        # There are a couple of things I don't do here, and are on purpose:
        #   - I want to fail if the file doesn't exist
        #   - I want to fail if the file doesn't contain valid JSON
        data = json.loads(file(db_file).read())

        # Here I don't do any error handling either, I expect the JSON files to
        # be valid
        self.id = data['id']
        self.title = data['title']
        self.description = self.handle_multiline_field(data['description'])
        self.severity = data['severity']
        self.wasc = data['wasc']
        self.tags = data['tags']
        self.cwe = data['cwe']
        self.owasp_top_10 = data['owasp_top_10']
        self.fix = ['fix']
        self.references = self.handle_references(data['references'])

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
        return self.handle_multiline_field(self.fix['effort'])

    def get_wasc_url(self, wasc_id):
        """
        :return: The URL associated with the wasc_id, usually the WASC ID is
                 received by the developer from self.wasc and he uses this
                 method to give the user a URL

                 None is returned if the URL can't be found
        """
        if wasc_id in WASC_ID_TO_URL:
            return WASC_ID_TO_URL[wasc_id]

    def get_cwe_url(self, cwe_id):
        """
        Similar to get_wasc_url() but for CWE
        """
        return CWE_URL_FMT % cwe_id

    def get_owasp_top_10_url(self, owasp_version, risk_id):
        """
        Similar to get_wasc_url() but for OWASP Top 10
        """
        if owasp_version == '2010':
            return OWASP_TOP10_2010_URL_FMT % risk_id
        elif owasp_version == '2013':
            return OWASP_TOP10_2013_URL_FMT % risk_id

    def handle_multiline_field(self, field_data):
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

    def handle_references(self, json_references):
        """
        Create a list of reference objects that represent this part of the JSON
        data:

          "references": [
              {"url": "http://foo.com/xss", "title": "First reference to XSS vulnerability"},
              {"url": "http://asp.net/xss", "title": "How to fix XSS vulns in ASP.NET"},
              {"url": "http://owasp.org/xss", "title": "OWASP desc for XSS"}
            ]

        :return: A list with Reference objects
        """
        reference_list = []
        for reference_dict in json_references:
            reference_list.append(Reference(reference_dict['url'],
                                            reference_dict['title']))

        return reference_list


class Reference(object):
    def __init__(self, url, title):
        self.url = url
        self.title = title