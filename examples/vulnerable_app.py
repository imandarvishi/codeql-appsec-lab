"""Deliberately vulnerable sample retained only for SAST training."""

import sqlite3

from flask import Flask, jsonify, request

app = Flask(__name__)


@app.get("/campaigns")
def campaigns():
    name = request.args.get("name", "")
    db = sqlite3.connect(":memory:")
    db.execute("CREATE TABLE campaigns (id INTEGER, name TEXT)")
    db.executemany("INSERT INTO campaigns VALUES (?, ?)", [(1, "Summer Demo"), (2, "Winter Demo")])

    # INTENTIONALLY VULNERABLE (CWE-89): do not copy into real applications.
    query = "SELECT id, name FROM campaigns WHERE name = '" + name + "'"
    rows = db.execute(query).fetchall()
    db.close()
    return jsonify([{"id": row[0], "name": row[1]} for row in rows])
