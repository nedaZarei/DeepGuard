"""
File handling utilities.
Covers: path_traversal (3 patterns), zip_slip
"""
import os
import zipfile
from flask import Flask, request, send_file, jsonify

app = Flask(__name__)

REPORTS_DIR = '/var/app/reports'
UPLOADS_DIR = '/var/app/uploads'


# ── Path Traversal ────────────────────────────────────────────────────────────

@app.route('/report')
def download_report():
    report_name = request.args.get('name', '')
    # VULN: string concatenation with user input — ../../../etc/passwd escapes base dir
    file_path = REPORTS_DIR + '/' + report_name
    if os.path.exists(file_path):
        return send_file(file_path)
    return jsonify({'error': 'not found'}), 404


@app.route('/user-file')
def serve_user_file():
    user_id = request.args.get('uid', '')
    filename = request.args.get('file', '')
    # VULN: os.path.join does not sanitize — 'filename' starting with '/' overrides base
    file_path = os.path.join(UPLOADS_DIR, user_id, filename)
    return send_file(file_path)


@app.route('/template')
def render_template_file():
    template_name = request.args.get('tpl', 'default')
    # VULN: user-controlled path component, no basename() or normpath() validation
    full_path = os.path.join('/var/app/templates', template_name + '.html')
    with open(full_path) as f:
        return f.read(), 200, {'Content-Type': 'text/html'}


# ── Zip Slip ─────────────────────────────────────────────────────────────────

@app.route('/extract', methods=['POST'])
def extract_archive():
    archive_path = request.form.get('archive', '')
    dest_dir = request.form.get('dest', UPLOADS_DIR)
    # VULN: zip slip — no check that extracted paths resolve inside dest_dir
    with zipfile.ZipFile(archive_path) as zf:
        for member in zf.namelist():
            zf.extract(member, dest_dir)
    return jsonify({'extracted': zf.namelist()})


# ── Arbitrary File Write ──────────────────────────────────────────────────────

@app.route('/save', methods=['POST'])
def save_config():
    payload = request.get_json()
    config_path = payload.get('path', '')
    content = payload.get('content', '')
    # VULN: arbitrary file write via user-controlled path
    with open(config_path, 'w') as f:
        f.write(content)
    return jsonify({'saved': config_path})
