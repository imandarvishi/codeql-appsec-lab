"""Hardened multi-tenant Flask API used by the advanced AppSec lab."""
from __future__ import annotations

import secrets
import sqlite3
import uuid
from contextlib import closing
from functools import wraps
from typing import Any, Callable, TypeVar, cast

from flask import Flask, Response, current_app, g, jsonify, request
from itsdangerous import BadSignature, SignatureExpired, URLSafeTimedSerializer

CAMPAIGNS = ((1, "tenant-red", "Summer Demo"), (2, "tenant-blue", "Winter Demo"),
             (3, "tenant-red", "Editor's Demo"))
MAX_NAME_LENGTH = 80
TOKEN_MAX_AGE_SECONDS = 900
F = TypeVar("F", bound=Callable[..., Any])


def create_app(test_config: dict[str, Any] | None = None) -> Flask:
    app = Flask(__name__)
    app.config.update(MAX_CONTENT_LENGTH=16 * 1024, JSON_SORT_KEYS=False,
                      SIGNING_KEY=secrets.token_urlsafe(32),
                      TOKEN_MAX_AGE_SECONDS=TOKEN_MAX_AGE_SECONDS)
    if test_config:
        app.config.update(test_config)
    app.extensions["security_audit"] = []

    @app.before_request
    def assign_request_id() -> None:
        supplied = request.headers.get("X-Request-ID", "")
        g.request_id = supplied if _valid_request_id(supplied) else str(uuid.uuid4())

    @app.after_request
    def harden_response(response: Response) -> Response:
        response.headers.update(
            {
                "X-Content-Type-Options": "nosniff",
                "X-Frame-Options": "DENY",
                "Referrer-Policy": "no-referrer",
                "Cache-Control": "no-store",
                "Content-Security-Policy": "default-src 'none'; frame-ancestors 'none'",
                "X-Request-ID": g.request_id,
            }
        )
        if response.status_code == 401:
            response.headers["WWW-Authenticate"] = "Bearer"
        return response

    @app.get("/health")
    def health() -> tuple[Response, int]:
        return jsonify({"status": "ok"}), 200

    @app.get("/campaigns")
    def campaigns() -> tuple[Response, int]:
        name = request.args.get("name", "", type=str)
        if not name:
            return jsonify([]), 200
        if len(name) > MAX_NAME_LENGTH or _contains_control_character(name):
            return _error("invalid_name", "name must be 1-80 printable characters", 400)
        with closing(_database()) as db:
            rows = db.execute("SELECT id, name FROM campaigns WHERE name = ?", (name,)).fetchall()
        return jsonify([{"id": row[0], "name": row[1]} for row in rows]), 200

    @app.get("/campaigns/<int:campaign_id>")
    @_require_access()
    def campaign_by_id(campaign_id: int) -> tuple[Response, int]:
        claims = cast(dict[str, str], g.claims)
        with closing(_database()) as db:
            row = db.execute("SELECT id, name FROM campaigns WHERE id = ? AND tenant_id = ?",
                             (campaign_id, claims["tenant"])).fetchone()
        _audit("campaign.read", "allowed" if row else "not_found", str(campaign_id))
        if not row:
            return _error("not_found", "resource not found", 404)
        return jsonify({"id": row[0], "name": row[1]}), 200

    @app.get("/admin/audit-events")
    @_require_access(required_role="security_admin")
    def audit_events() -> tuple[Response, int]:
        _audit("audit.read", "allowed")
        return jsonify(list(app.extensions["security_audit"])), 200

    @app.errorhandler(404)
    def not_found(_error_value: Exception) -> tuple[Response, int]:
        return _error("not_found", "resource not found", 404)

    @app.errorhandler(413)
    def payload_too_large(_error_value: Exception) -> tuple[Response, int]:
        return _error("payload_too_large", "request body exceeds 16 KiB", 413)
    return app


def issue_demo_token(subject: str, tenant: str, role: str = "viewer") -> str:
    """Issue a lab token; production systems should use a managed identity provider."""
    return _serializer().dumps({"sub": subject, "tenant": tenant, "role": role})


def _require_access(required_role: str | None = None) -> Callable[[F], F]:
    def decorator(function: F) -> F:
        @wraps(function)
        def wrapper(*args: Any, **kwargs: Any) -> Any:
            scheme, separator, token = request.headers.get("Authorization", "").partition(" ")
            if not separator or scheme.lower() != "bearer" or not token:
                _audit("authentication", "missing")
                return _error("unauthorized", "valid bearer token required", 401)
            try:
                claims = _serializer().loads(token, max_age=int(
                    current_app.config["TOKEN_MAX_AGE_SECONDS"]))
            except SignatureExpired:
                _audit("authentication", "expired")
                return _error("unauthorized", "token expired", 401)
            except BadSignature:
                _audit("authentication", "invalid")
                return _error("unauthorized", "valid bearer token required", 401)
            if not _valid_claims(claims):
                _audit("authentication", "invalid_claims")
                return _error("unauthorized", "valid bearer token required", 401)
            g.claims = claims
            if required_role and claims["role"] != required_role:
                _audit("authorization", "denied")
                return _error("forbidden", "insufficient role", 403)
            return function(*args, **kwargs)
        return cast(F, wrapper)
    return decorator


def _serializer() -> URLSafeTimedSerializer:
    return URLSafeTimedSerializer(current_app.config["SIGNING_KEY"], salt="appsec-lab-access")


def _valid_claims(value: Any) -> bool:
    return isinstance(value, dict) and all(isinstance(value.get(key), str) and value[key]
                                           for key in ("sub", "tenant", "role"))


def _database() -> sqlite3.Connection:
    db = sqlite3.connect(":memory:")
    db.execute("CREATE TABLE campaigns (id INTEGER PRIMARY KEY, tenant_id TEXT NOT NULL, "
               "name TEXT NOT NULL UNIQUE)")
    db.executemany("INSERT INTO campaigns VALUES (?, ?, ?)", CAMPAIGNS)
    return db


def _audit(action: str, outcome: str, target: str | None = None) -> None:
    claims = getattr(g, "claims", {})
    event = {"action": action, "outcome": outcome, "subject": claims.get("sub", "anonymous"),
             "tenant": claims.get("tenant", "unknown"), "target": target,
             "request_id": g.request_id}
    events = current_app.extensions["security_audit"]
    events.append(event)
    del events[:-100]


def _error(code: str, message: str, status: int) -> tuple[Response, int]:
    return jsonify({"error": {"code": code, "message": message},
                    "request_id": g.request_id}), status


def _contains_control_character(value: str) -> bool:
    return any(ord(character) < 32 or ord(character) == 127 for character in value)


def _valid_request_id(value: str) -> bool:
    return bool(value) and len(value) <= 64 and value.replace("-", "").replace("_", "").isalnum()


app = create_app()
if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5000, debug=False)
