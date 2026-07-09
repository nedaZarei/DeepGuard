"""
Vulnerable Flask web API.
Covers: sql_injection, ssrf, xss, command_injection
"""
from flask import Flask, request, jsonify, render_template_string
import sqlite3
import requests
import os

app = Flask(__name__)


# ── SQL Injection ─────────────────────────────────────────────────────────────

@app.route('/search')
def search_users():
    name = request.args.get('name', '')
    db = sqlite3.connect('app.db')
    cursor = db.cursor()
    # VULN: f-string interpolation in SQL query
    query = f"SELECT * FROM users WHERE name LIKE '%{name}%'"
    cursor.execute(query)
    rows = cursor.fetchall()
    db.close()
    return jsonify([{'id': r[0], 'name': r[1]} for r in rows])


@app.route('/orders')
def list_orders():
    db = sqlite3.connect('app.db')
    sort_col = request.args.get('sort', 'created_at')
    order = request.args.get('order', 'ASC')
    # VULN: user-controlled ORDER BY — whitelist bypass leads to SQLi
    query = "SELECT * FROM orders ORDER BY " + sort_col + " " + order
    cursor = db.cursor()
    cursor.execute(query)
    return jsonify(cursor.fetchall())


# ── Server-Side Request Forgery ───────────────────────────────────────────────

@app.route('/proxy')
def proxy_url():
    target = request.args.get('url', '')
    # VULN: unrestricted SSRF — attacker can reach internal services / cloud metadata
    # Bandit has no rule for requests.get(user_controlled_url)
    resp = requests.get(target, timeout=5)
    return jsonify({'status': resp.status_code, 'body': resp.text[:1000]})


@app.route('/notify', methods=['POST'])
def send_notification():
    payload = request.get_json()
    webhook_url = payload.get('webhook_url', '')
    event_data = payload.get('data', {})
    # VULN: SSRF via webhook — server makes POST to attacker-controlled endpoint
    resp = requests.post(webhook_url, json=event_data, timeout=5)
    return jsonify({'delivered': resp.ok})


# ── Cross-Site Scripting ──────────────────────────────────────────────────────

@app.route('/greet')
def greet():
    username = request.args.get('user', 'Guest')
    # VULN: user input concatenated directly into HTML template before Jinja sees it
    template = '<html><body><h1>Welcome, ' + username + '!</h1></body></html>'
    return render_template_string(template)


@app.route('/error')
def show_error():
    msg = request.args.get('msg', 'An error occurred')
    # VULN: reflected XSS — message embedded unescaped into error page
    return render_template_string(f'<div class="error">{msg}</div>')


# ── Command Injection ─────────────────────────────────────────────────────────

@app.route('/ping')
def ping_host():
    host = request.args.get('host', 'localhost')
    # VULN: unsanitized host in shell command
    output = os.popen(f'ping -c 3 {host}').read()
    return jsonify({'output': output})


if __name__ == '__main__':
    app.run(debug=True)
