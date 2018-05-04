import unittest
import os

from vulndb import DBVuln
from vulndb.db_vuln import Reference

MOCK_TITLE = 'Title'
MOCK_DESC = 'Description for the vulnerability'
MOCK_ID = 123
MOCK_SEVERITY = 'medium'
MOCK_WASC = ['2']
MOCK_TAGS = ['hello', 'world']
MOCK_CWE = ['89']
MOCK_OWASP_TOP_10 = {"2010": [1], "2013": [2]}
MOCK_FIX_EFFORT = 50
MOCK_FIX_GUIDANCE = "A very long text explaining how to fix..."
MOCK_DB_FILE = 'path/to/file.json'
MOCK_REFERENCES = [{"url": "http://foo.com/xss",
                    "title": "First reference to XSS vulnerability"},
                   {"url": "http://asp.net/xss",
                    "title": "How to fix XSS vulns in ASP.NET"}]


class TestDBVuln(unittest.TestCase):
    DEFAULT_KWARGS = {
            '_id': MOCK_ID,
            'title': MOCK_TITLE,
            'description': MOCK_DESC,
            'severity': MOCK_SEVERITY,
            'wasc': MOCK_WASC,
            'tags': MOCK_TAGS,
            'cwe': MOCK_CWE,
            'owasp_top_10': MOCK_OWASP_TOP_10,
            'fix_effort': MOCK_FIX_EFFORT,
            'fix_guidance': MOCK_FIX_GUIDANCE,
            'references': MOCK_REFERENCES,
            'db_file': MOCK_DB_FILE
        }

    def setUp(self):
        self.original_db_path = DBVuln.DB_PATH

        current_dir = os.path.dirname(os.path.realpath(__file__))
        DBVuln.DB_PATH = os.path.join(current_dir, 'db')

    def tearDown(self):
        DBVuln.DB_PATH = self.original_db_path

    def test_basic(self):
        dbv = DBVuln(**self.DEFAULT_KWARGS)

        self.assertEqual(dbv.title, MOCK_TITLE)
        self.assertEqual(dbv.description, MOCK_DESC)
        self.assertEqual(dbv.id, MOCK_ID)
        self.assertEqual(dbv.severity, MOCK_SEVERITY)
        self.assertEqual(dbv.wasc, MOCK_WASC)
        self.assertEqual(dbv.tags, MOCK_TAGS)
        self.assertEqual(dbv.cwe, MOCK_CWE)
        self.assertEqual(dbv.owasp_top_10, MOCK_OWASP_TOP_10)
        self.assertEqual(dbv.fix_effort, MOCK_FIX_EFFORT)
        self.assertEqual(dbv.fix_guidance, MOCK_FIX_GUIDANCE)
        self.assertEqual(dbv.references, MOCK_REFERENCES)
        self.assertEqual(dbv.db_file, MOCK_DB_FILE)

    def test_from_file(self):
        _file = os.path.join(DBVuln.DB_PATH, DBVuln.DEFAULT_LANG, '123-spec-example.json')

        dbv_1 = DBVuln.from_file(_file)
        dbv_2 = DBVuln.from_id(123)

        self.assertEqual(dbv_1, dbv_2)
        self.assertEqual(dbv_1.db_file, _file)

    def test_from_id(self):
        dbv = DBVuln.from_id(123)

        _file = os.path.join(DBVuln.DB_PATH, DBVuln.DEFAULT_LANG, '123-spec-example.json')
        self.assertEqual(dbv.db_file, _file)

        expected_references = [Reference("http://foo.com/xss",
                                         "First reference to XSS vulnerability"),
                               Reference("http://asp.net/xss",
                                         "How to fix XSS vulns in ASP.NET")]

        self.assertEqual(dbv.title, u'Cross-Site Scripting')
        self.assertEqual(dbv.description, u'A very long text explaining what a XSS'
                                          u' vulnerability is')
        self.assertEqual(dbv.id, MOCK_ID)
        self.assertEqual(dbv.severity, MOCK_SEVERITY)
        self.assertEqual(dbv.wasc, [u'0003'])
        self.assertEqual(dbv.tags, [u'xss', u'client side'])
        self.assertEqual(dbv.cwe, [u'0003', u'0007'])
        self.assertEqual(dbv.owasp_top_10, {"2010": [1], "2013": [2]},)
        self.assertEqual(dbv.references, expected_references)
        self.assertEqual(dbv.fix_effort, 50)
        self.assertEqual(dbv.fix_guidance, u'A very long text explaining how developers'
                                           u' should prevent\nXSS vulnerabilities.\n')

    def test_get_cwe_url(self):
        dbv = DBVuln(**self.DEFAULT_KWARGS)
        self.assertEqual(dbv.get_cwe_url(89),
                         'https://cwe.mitre.org/data/definitions/89.html')

    def test_get_wasc_url(self):
        dbv = DBVuln(**self.DEFAULT_KWARGS)
        self.assertEqual(dbv.get_wasc_url(3),
                         'http://projects.webappsec.org/w/page/13246946/Integer%20Overflows')

    def test_get_owasp_top_10_url(self):
        dbv = DBVuln(**self.DEFAULT_KWARGS)
        self.assertEqual(dbv.get_owasp_top_10_url(2010, 2),
                         'https://www.owasp.org/index.php/Top_10_2010-A2')

        self.assertEqual(dbv.get_owasp_top_10_url(2013, 2),
                         'https://www.owasp.org/index.php/Top_10_2013-A2')

        self.assertEqual(dbv.get_owasp_top_10_url(2033, 2), None)

    def test_load_es_lang(self):
        language = 'es'
        _file = os.path.join(DBVuln.DB_PATH, language, '123-spec-example.json')

        dbv_1 = DBVuln.from_file(_file, language=language)
        dbv_2 = DBVuln.from_id(123, language=language)

        self.assertEqual(dbv_1, dbv_2)
        self.assertEqual(dbv_1.db_file, _file)

        dbv = dbv_1

        expected_references = [Reference("http://foo.es/xss",
                                         "Primera referencia a una vulnerabilidad de XSS"),
                               Reference("http://asp.net/xss",
                                         "Como arreglar XSS en .NET")]

        self.assertEqual(dbv.title, u'Cross-Site Scripting en ES')
        self.assertEqual(dbv.description, u'Un texto largo donde se explica que es un XSS')
        self.assertEqual(dbv.id, MOCK_ID)
        self.assertEqual(dbv.severity, MOCK_SEVERITY)
        self.assertEqual(dbv.wasc, [u'0003'])
        self.assertEqual(dbv.tags, [u'xss', u'client side'])
        self.assertEqual(dbv.cwe, [u'0003', u'0007'])
        self.assertEqual(dbv.owasp_top_10, {"2010": [1], "2013": [2]},)
        self.assertEqual(dbv.references, expected_references)
        self.assertEqual(dbv.fix_effort, 50)
        self.assertEqual(dbv.fix_guidance, u'Y otro texto largo donde se explica como'
                                           u' arreglar vulnerabilidades de XSS')