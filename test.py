import unittest
import sys
sys.path.insert(0, 'app/')
import routes

    
class FlaskrTestCase(unittest.TestCase):

    def setUp(self):
        pass

    def tearDown(self):
        pass

    def test_empty_db(self):
        self.assertTrue(Certificate.IsValid(all_cert[2]))


if __name__ == '__main__':
    unittest.main()
