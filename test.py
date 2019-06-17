import unittest
import sys
from app.routes import *
    
class FlaskrTestCase(unittest.TestCase):

    def setUp(self):
        pass

    def tearDown(self):
        pass

    def test_my_file(self):
        self.assertFalse(Certificate.IsValid(all_cert[0]))
        self.assertFalse(Certificate.IsValid(all_cert[1]))
        self.assertTrue(Certificate.IsValid(all_cert[2]))


if __name__ == '__main__':
    unittest.main()
