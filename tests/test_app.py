"""Behavioural and security regression tests for the hardened application."""

import unittest

from app import create_app


class CampaignSecurityTests(unittest.TestCase):
    def setUp(self) -> None:
        self.app = create_app()
        self.app.config["TESTING"] = True
        self.client = self.app.test_client()

    def search(self, value: str):
        return self.client.get("/campaigns", query_string={"name": value})

    def test_health(self) -> None:
        response = self.client.get("/health")
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.get_json(), {"status": "ok"})

    def test_exact_match(self) -> None:
        response = self.search("Summer Demo")
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.get_json(), [{"id": 1, "name": "Summer Demo"}])

    def test_unknown_and_empty_names_return_no_records(self) -> None:
        self.assertEqual(self.search("Missing Demo").get_json(), [])
        self.assertEqual(self.client.get("/campaigns").get_json(), [])

    def test_sql_injection_is_treated_as_data(self) -> None:
        response = self.search("' OR 1=1 --")
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.get_json(), [])

    def test_union_payload_is_treated_as_data(self) -> None:
        response = self.search("' UNION SELECT 99, 'owned' --")
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.get_json(), [])

    def test_legitimate_apostrophe_is_supported(self) -> None:
        response = self.search("Editor's Demo")
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.get_json(), [{"id": 3, "name": "Editor's Demo"}])

    def test_overlong_name_is_rejected(self) -> None:
        response = self.search("A" * 81)
        self.assertEqual(response.status_code, 400)
        self.assertEqual(response.get_json()["error"]["code"], "invalid_name")

    def test_control_character_is_rejected(self) -> None:
        response = self.search("Summer\nDemo")
        self.assertEqual(response.status_code, 400)

    def test_security_headers_are_present(self) -> None:
        response = self.client.get("/health")
        self.assertEqual(response.headers["X-Content-Type-Options"], "nosniff")
        self.assertEqual(response.headers["X-Frame-Options"], "DENY")
        self.assertEqual(response.headers["Cache-Control"], "no-store")
        self.assertIn("default-src 'none'", response.headers["Content-Security-Policy"])

    def test_valid_request_id_is_preserved(self) -> None:
        response = self.client.get("/health", headers={"X-Request-ID": "interview-demo-123"})
        self.assertEqual(response.headers["X-Request-ID"], "interview-demo-123")

    def test_untrusted_request_id_is_replaced(self) -> None:
        response = self.client.get("/health", headers={"X-Request-ID": "bad value!"})
        self.assertNotEqual(response.headers["X-Request-ID"], "bad value!")

    def test_404_is_json_without_stack_trace(self) -> None:
        response = self.client.get("/does-not-exist")
        self.assertEqual(response.status_code, 404)
        self.assertEqual(response.get_json()["error"]["code"], "not_found")
        self.assertNotIn(b"Traceback", response.data)


if __name__ == "__main__":
    unittest.main()
