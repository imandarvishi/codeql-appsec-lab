"""Intentionally vulnerable SQL injection training app. Synthetic data only."""
import sqlite3

from flask import Flask, jsonify, request

app = Flask(__name__)


@app.get('/campaigns')
def campaigns():
    # A fresh in-memory database makes the exercise isolated and repeatable.
    name = request.args.get('name', '')
    db = sqlite3.connect(':memory:')
    try:
        db.execute('CREATE TABLE campaigns (id INTEGER, name TEXT)')
        db.executemany('INSERT INTO campaigns VALUES (?, ?)', [
            (1, 'Summer Demo'), (2, 'Winter Demo'), (3, "Editor's Demo")
        ])
        # TRAINING BUG: untrusted request input changes the SQL statement.
        query = "SELECT id, name FROM campaigns WHERE name = '" + name + "'"
        rows = db.execute(query).fetchall()
        return jsonify([{'id': row[0], 'name': row[1]} for row in rows])
    finally:
        db.close()


if __name__ == '__main__':
    app.run(host='127.0.0.1', port=5000, debug=False)
