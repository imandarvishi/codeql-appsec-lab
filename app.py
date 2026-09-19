"""Hardened Flask application used by the advanced AppSec lab."""

from __future__ import annotations

import sqlite3
import uuid
from contextlib import closing

from flask import Flask, Response, g, jsonify, request

CAMPAIGNS = (
    (1, "Summer Demo"),
    (2, "Winter Demo"),
    (3, "Editor's Demo"),
)
MAX_NAME_LENGTH = 80


def create_app() -> Flask:
    app = Flask(__name__)
    app.config.update(MAX_CONTENT_LENGTH=16 * 1024, JSON_SORT_KEYS=False)

    @app.before_request
    def assign_request_id() -> None:
        supplied = request.headers.get("X-Request-ID", "")
        g.request_id = supplied if _valid_request_id(supplied) else str(uuid.uuid4())

    @app.after_request
    def harden_response(response: Response) -> Response:
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["Referrer-Policy"] = "no-referrer"
        response.headers["Content-Security-Policy"] = "default-src 'none'; frame-ancestors 'none'"
        response.headers["Cache-Control"] = "no-store"
        response.headers["X-Request-ID"] = g.request_id
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
            rows = db.execute(
                "SELECT id, name FROM campaigns WHERE name = ?",
                (name,),
            ).fetchall()
        return jsonify([{"id": row[0], "name": row[1]} for row in rows]), 200

    @app.errorhandler(404)
    def not_found(_error_value: Exception) -> tuple[Response, int]:
        return _error("not_found", "resource not found", 404)

    @app.errorhandler(413)
    def payload_too_large(_error_value: Exception) -> tuple[Response, int]:
        return _error("payload_too_large", "request body exceeds 16 KiB", 413)

    return app


def _database() -> sqlite3.Connection:
    db = sqlite3.connect(":memory:")
    db.execute("CREATE TABLE campaigns (id INTEGER PRIMARY KEY, name TEXT NOT NULL UNIQUE)")
    db.executemany("INSERT INTO campaigns VALUES (?, ?)", CAMPAIGNS)
    return db


def _error(code: str, message: str, status: int) -> tuple[Response, int]:
    payload = {"error": {"code": code, "message": message}, "request_id": g.request_id}
    return jsonify(payload), status


def _contains_control_character(value: str) -> bool:
    return any(ord(character) < 32 or ord(character) == 127 for character in value)


def _valid_request_id(value: str) -> bool:
    return bool(value) and len(value) <= 64 and value.replace("-", "").replace("_", "").isalnum()


app = create_app()


if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5000, debug=False)
