"""
Data processing utilities.
Covers: insecure_deserialization, command_injection, xxe, crypto_issue (weak random)
"""
import pickle
import base64
import subprocess
import random
import string
import xml.etree.ElementTree as ET


# ── Insecure Deserialization ──────────────────────────────────────────────────

def restore_object(serialized: str):
    """Restore a Python object from a base64-encoded pickle payload."""
    # VULN: pickle.loads on untrusted data enables arbitrary code execution
    raw = base64.b64decode(serialized)
    return pickle.loads(raw)


def load_job_state(state_bytes: bytes):
    """Resume a background job from its saved state."""
    # VULN: pickle.loads without any source validation
    return pickle.loads(state_bytes)


# ── Command Injection ─────────────────────────────────────────────────────────

def convert_document(input_path: str, output_format: str) -> str:
    """Convert a document using an external tool."""
    # VULN: user-controlled output_format injected into shell command
    result = subprocess.run(
        f'pandoc {input_path} -o output.{output_format}',
        shell=True, capture_output=True, text=True
    )
    return result.stdout


def run_analysis(dataset_name: str) -> dict:
    """Run an analysis script against the named dataset."""
    # VULN: dataset_name appended to shell command without sanitization
    out = subprocess.check_output(
        'python3 scripts/analyze.py --dataset ' + dataset_name,
        shell=True, text=True
    )
    return {'output': out}


# ── XML External Entity (XXE) ─────────────────────────────────────────────────

def parse_report_xml(xml_string: str) -> dict:
    """Parse an XML report submitted by a client."""
    # VULN: ElementTree is safe by default in CPython 3.8+, but lxml without
    # resolve_entities=False is not. Using defusedxml is the secure alternative.
    # This pattern is unsafe when xml_string comes from an untrusted source
    # and the runtime uses a vulnerable parser (e.g., libxml2 via lxml).
    import lxml.etree as lxml_et
    # VULN: lxml parses external entities by default
    parser = lxml_et.XMLParser()
    root = lxml_et.fromstring(xml_string.encode(), parser)
    return {child.tag: child.text for child in root}


def parse_config_xml(xml_data: bytes) -> ET.Element:
    """Parse an XML configuration blob."""
    # VULN: xml.etree.ElementTree does not protect against billion-laughs / entity expansion
    # on Python < 3.8; acceptable to flag as informational on modern Python
    return ET.fromstring(xml_data)


# ── Weak Random ───────────────────────────────────────────────────────────────

def generate_session_token(length: int = 32) -> str:
    """Generate a session token."""
    # VULN: random.choice is not cryptographically secure; use secrets.token_hex
    alphabet = string.ascii_letters + string.digits
    return ''.join(random.choice(alphabet) for _ in range(length))


def generate_password_reset_link(user_id: int) -> str:
    """Create a password reset URL."""
    # VULN: predictable token — random.randint seeded from system time is guessable
    token = random.randint(100000, 999999)
    return f'https://app.example.com/reset?uid={user_id}&token={token}'
