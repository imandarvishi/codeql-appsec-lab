"""Behavioural, authorization and security-property tests."""
import unittest

from hypothesis import given, settings
from hypothesis import strategies as st

from app import create_app, issue_demo_token


class CampaignSecurityTests(unittest.TestCase):
    def setUp(self) -> None:
        self.app = create_app({"TESTING": True, "SIGNING_KEY": "test-only-key"})
        self.client = self.app.test_client()

    def authorization(self, tenant: str = "tenant-red", role: str = "viewer") -> dict[str, str]:
        with self.app.app_context():
            token = issue_demo_token("test-user", tenant, role)
        return {"Authorization": f"Bearer {token}"}

    def search(self, value: str):
        return self.client.get("/campaigns", query_string={"name": value})

    def test_health(self) -> None:
        self.assertEqual(self.client.get("/health").get_json(), {"status": "ok"})

    def test_exact_match_and_apostrophe(self) -> None:
        self.assertEqual(self.search("Summer Demo").get_json(), [{"id": 1, "name": "Summer Demo"}])
        self.assertEqual(self.search("Editor's Demo").get_json(),
                         [{"id": 3, "name": "Editor's Demo"}])

    def test_sql_injection_payloads_are_data(self) -> None:
        for payload in ("' OR 1=1 --", "' UNION SELECT 99, 'owned' --", "'; DROP TABLE x; --"):
            with self.subTest(payload=payload):
                response = self.search(payload)
                self.assertEqual(response.status_code, 200)
                self.assertEqual(response.get_json(), [])

    @settings(max_examples=40, deadline=None)
    @given(st.text(max_size=80))
    def test_arbitrary_search_never_returns_multiple_records(self, value: str) -> None:
        response = self.search(value)
        if any(ord(character) < 32 or ord(character) == 127 for character in value):
            self.assertEqual(response.status_code, 400)
        else:
            self.assertEqual(response.status_code, 200)
            self.assertLessEqual(len(response.get_json()), 1)

    def test_invalid_input_is_rejected(self) -> None:
        self.assertEqual(self.search("A" * 81).status_code, 400)
        self.assertEqual(self.search("Summer\nDemo").status_code, 400)

    def test_protected_resource_requires_token(self) -> None:
        response = self.client.get("/campaigns/1")
        self.assertEqual(response.status_code, 401)
        self.assertEqual(response.headers["WWW-Authenticate"], "Bearer")

    def test_tampered_token_is_rejected(self) -> None:
        header = self.authorization()
        header["Authorization"] += "tampered"
        self.assertEqual(self.client.get("/campaigns/1", headers=header).status_code, 401)

    def test_tenant_can_read_own_resource(self) -> None:
        response = self.client.get("/campaigns/1", headers=self.authorization("tenant-red"))
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.get_json(), {"id": 1, "name": "Summer Demo"})

    def test_bola_cross_tenant_access_is_hidden(self) -> None:
        response = self.client.get("/campaigns/2", headers=self.authorization("tenant-red"))
        self.assertEqual(response.status_code, 404)

    def test_audit_endpoint_requires_admin_role(self) -> None:
        denied = self.client.get("/admin/audit-events", headers=self.authorization(role="viewer"))
        self.assertEqual(denied.status_code, 403)
        allowed = self.client.get("/admin/audit-events",
                                  headers=self.authorization(role="security_admin"))
        self.assertEqual(allowed.status_code, 200)
        self.assertGreaterEqual(len(allowed.get_json()), 1)

    def test_security_decision_is_audited_without_token(self) -> None:
        self.client.get("/campaigns/1", headers=self.authorization("tenant-red"))
        event = self.app.extensions["security_audit"][-1]
        self.assertEqual(event["action"], "campaign.read")
        self.assertNotIn("Authorization", event)

    def test_security_headers_and_request_id(self) -> None:
        response = self.client.get("/health", headers={"X-Request-ID": "interview-demo-123"})
        self.assertEqual(response.headers["X-Request-ID"], "interview-demo-123")
        self.assertEqual(response.headers["X-Content-Type-Options"], "nosniff")
        self.assertEqual(response.headers["X-Frame-Options"], "DENY")
        self.assertEqual(response.headers["Cache-Control"], "no-store")

    def test_untrusted_request_id_is_replaced(self) -> None:
        response = self.client.get("/health", headers={"X-Request-ID": "bad value!"})
        self.assertNotEqual(response.headers["X-Request-ID"], "bad value!")

    def test_404_is_json_without_stack_trace(self) -> None:
        response = self.client.get("/does-not-exist")
        self.assertEqual(response.status_code, 404)
        self.assertNotIn(b"Traceback", response.data)


if __name__ == "__main__":
    unittest.main()
