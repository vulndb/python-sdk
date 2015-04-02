import shutil
import unittest
import subprocess

from vulndb.db_vuln import DBVuln

VULNDB_DATA = 'https://github.com/vulndb/data.git'
LATEST_COMMIT = 'git rev-parse HEAD'


class TestLatestDBUsed(unittest.TestCase):
    def test_latest_db_used(self):
        subprocess.check_output('git clone %s' % VULNDB_DATA,
                                shell=True, cwd='/tmp/')
        latest_commit = subprocess.check_output(LATEST_COMMIT,
                                                shell=True, cwd='/tmp/data/')

        shutil.rmtree('/tmp/data/')

        latest_commit = latest_commit.strip()
        latest_saved_commit = DBVuln.get_db_version()

        self.assertEqual(latest_commit, latest_saved_commit)
