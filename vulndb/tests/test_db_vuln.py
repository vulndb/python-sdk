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
MOCK_FIX = {"guidance": "A very long text explaining how to fix...",
            "effort": 50}
MOCK_REFERENCES = [{"url": "http://foo.com/xss", "title": "First reference to XSS vulnerability"},
                   {"url": "http://asp.net/xss", "title": "How to fix XSS vulns in ASP.NET"}]


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
            'fix': MOCK_FIX,
            'references': MOCK_REFERENCES,
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
        self.assertEqual(dbv.fix, MOCK_FIX)
        self.assertEqual(dbv.references, MOCK_REFERENCES)

    def test_from_file(self):
        _file = os.path.join(DBVuln.DB_PATH, '123-spec-example.json')

        dbv_1 = DBVuln.from_file(_file)
        dbv_2 = DBVuln.from_id(123)

        self.assertEqual(dbv_1, dbv_2)

    def test_from_id(self):
        dbv = DBVuln.from_id(123)

        expected_references = [Reference("http://foo.com/xss",
                                         "First reference to XSS vulnerability"),
                               Reference("http://asp.net/xss",
                                         "How to fix XSS vulns in ASP.NET")]

        self.assertEqual(dbv.title, u'Cross-Site Scripting')
        self.assertEqual(dbv.description, u'A very long description for'
                                          u' Cross-Site Scripting')
        self.assertEqual(dbv.id, MOCK_ID)
        self.assertEqual(dbv.severity, MOCK_SEVERITY)
        self.assertEqual(dbv.wasc, [u'0003'])
        self.assertEqual(dbv.tags, [u'xss', u'client side'])
        self.assertEqual(dbv.cwe, [u'0003', u'0007'])
        self.assertEqual(dbv.owasp_top_10, {"2010": [1], "2013": [2]},)
        self.assertEqual(dbv.fix, {u"guidance": u"A very long text explaining"
                                                u" how to fix XSS"
                                                u" vulnerabilities",
                                   u"effort": 50})
        self.assertEqual(dbv.references, expected_references)
        self.assertEqual(dbv.fix_effort, 50)
        self.assertEqual(dbv.fix_guidance, u"A very long text explaining"
                                           u" how to fix XSS vulnerabilities")

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

    def test_long_lines(self):
        dbv = DBVuln.from_id(124)
        self.assertEqual(dbv.description, u'A very long description for'
                                          u' Cross-Site Scripting')

    def test_long_lines_with_new_line(self):
        dbv = DBVuln.from_id(125)
        self.assertEqual(dbv.description, u'Start line 1\n'
                                          u'Start line 2\n')
