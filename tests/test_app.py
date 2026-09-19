"""Security requirements: two tests deliberately fail on the starter app."""
import unittest

from app import app


class CampaignSecurityTests(unittest.TestCase):
    def setUp(self):
        app.config['TESTING'] = True
        self.client = app.test_client()

    def search(self, value):
        return self.client.get('/campaigns', query_string={'name': value})

    def test_exact_match(self):
        response = self.search('Summer Demo')
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.get_json(), [{'id': 1, 'name': 'Summer Demo'}])

    def test_unknown_name(self):
        self.assertEqual(self.search('Missing Demo').get_json(), [])

    def test_empty_name(self):
        self.assertEqual(self.client.get('/campaigns').get_json(), [])

    def test_sql_injection_does_not_return_all_records(self):
        response = self.search("' OR 1=1 --")
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.get_json(), [])

    def test_legitimate_apostrophe_is_supported(self):
        response = self.search("Editor's Demo")
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.get_json(), [{'id': 3, 'name': "Editor's Demo"}])


if __name__ == '__main__':
    unittest.main()
