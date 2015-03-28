import subprocess
import unittest


class TestDataIsInstalled(unittest.TestCase):
    TEST_CMD = "python -c 'from vulndb import DBVuln; DBVuln.from_id(123)'"

    def test_data_is_installed_in_virtualenv(self):
        # When we run this in the current CMD it will load the python class
        # and db files from this directory (because of python's PATH)
        subprocess.check_output(self.TEST_CMD, shell=True)

        subprocess.check_output('python setup.py install', shell=True)
        # Now we run it in /tmp , where there is no vulndb in current PATH
        # so it will try to find it inside the site-packages
        subprocess.check_output(self.TEST_CMD, shell=True, cwd='/tmp/')
