"""
Vulnerable Flask API for smoke testing
"""
from flask import Flask, request, jsonify, send_file
import sqlite3
import os

app = Flask(__name__)

# Database connection
def get_db():
    return sqlite3.connect('app.db')

# SQL Injection vulnerability
@app.route('/users/<user_id>')
def get_user(user_id):
    db = get_db()
    cursor = db.cursor()

    # VULNERABLE: String formatting in SQL query
    query = "SELECT * FROM users WHERE id = %s" % user_id
    cursor.execute(query)

    result = cursor.fetchone()
    db.close()

    if result:
        return jsonify({'id': result[0], 'name': result[1]})
    return jsonify({'error': 'User not found'}), 404

# SQL Injection with f-string
@app.route('/search')
def search():
    term = request.args.get('q', '')
    db = get_db()
    cursor = db.cursor()

    # VULNERABLE: f-string in SQL query
    query = f"SELECT * FROM products WHERE name LIKE '%{term}%'"
    cursor.execute(query)

    results = cursor.fetchall()
    db.close()

    return jsonify([{'id': r[0], 'name': r[1]} for r in results])

# Path Traversal vulnerability
@app.route('/download')
def download_file():
    filename = request.args.get('file', '')

    # VULNERABLE: No path validation
    file_path = os.path.join('/var/www/uploads', filename)

    if os.path.exists(file_path):
        return send_file(file_path)
    return jsonify({'error': 'File not found'}), 404

# Command Injection vulnerability
@app.route('/ping')
def ping():
    host = request.args.get('host', 'localhost')

    # VULNERABLE: Unsanitized command execution
    result = os.popen(f'ping -c 1 {host}').read()

    return jsonify({'result': result})

if __name__ == '__main__':
    app.run(debug=True)
