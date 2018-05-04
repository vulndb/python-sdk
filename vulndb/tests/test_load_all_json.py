import unittest
import types
import os

from vulndb import DBVuln
from vulndb.db_vuln import Reference


class TestLoadAllJSON(unittest.TestCase):

    maxDiff = None

    def test_from_file(self):
        failed_json_files = []
        processed_files = []

        for language in DBVuln.get_all_languages():

            json_path = os.path.join(DBVuln.DB_PATH, language)

            for _fname in os.listdir(json_path):
                _file_path = os.path.join(json_path, _fname)

                if os.path.isdir(_file_path):
                    continue

                try:
                    DBVuln.LANG = language
                    dbv = DBVuln.from_file(_file_path)
                except:
                    failed_json_files.append(_fname)
                    continue

                processed_files.append(_fname)

                self.assertIsInstance(dbv.title, basestring)
                self.assertIsInstance(dbv.description, basestring)
                self.assertIsInstance(dbv.id, int)
                self.assertIsInstance(dbv.severity, basestring)
                self.assertIsInstance(dbv.wasc, (types.NoneType, list))
                self.assertIsInstance(dbv.tags, (types.NoneType, list))
                self.assertIsInstance(dbv.cwe, (types.NoneType, list))
                self.assertIsInstance(dbv.owasp_top_10, (types.NoneType, dict))
                self.assertIsInstance(dbv.fix_effort, int)
                self.assertIsInstance(dbv.fix_guidance, basestring)

                for ref in dbv.references:
                    self.assertIsInstance(ref, Reference)

            self.assertEqual(failed_json_files, [])
            self.assertGreater(len(processed_files), 20)

