import unittest
import types
import os

from vulndb import DBVuln
from vulndb.db_vuln import Reference


class TestLoadAllJSON(unittest.TestCase):
    def test_from_file(self):
        for _fname in os.listdir(DBVuln.DB_PATH):
            _file_path = os.path.join(DBVuln.DB_PATH, _fname)

            dbv = DBVuln.from_file(_file_path)

            self.assertIsInstance(dbv.title, basestring)
            self.assertIsInstance(dbv.description, basestring)
            self.assertIsInstance(dbv.id, int)
            self.assertIsInstance(dbv.severity, basestring)
            self.assertIsInstance(dbv.wasc, (types.NoneType, list))
            self.assertIsInstance(dbv.tags, (types.NoneType, list))
            self.assertIsInstance(dbv.cwe, (types.NoneType, list))
            self.assertIsInstance(dbv.owasp_top_10, (types.NoneType, dict))
            self.assertIsInstance(dbv.fix, dict)
            self.assertIsInstance(dbv.fix_effort, int)
            self.assertIsInstance(dbv.fix_guidance, basestring)

            for ref in dbv.references:
                self.assertIsInstance(ref, Reference)
