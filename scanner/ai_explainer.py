import json
import os
import sys
import urllib.error
import urllib.request
from functools import lru_cache
from typing import Tuple

from .port_info import get_static_description

try:
    import google.generativeai as genai  # type: ignore
except Exception:
    genai = None


DEFAULT_GEMINI_MODEL = os.getenv('GEMINI_MODEL', 'gemini-2.5-flash')
DEFAULT_GROQ_MODEL = os.getenv('GROQ_MODEL', 'llama-3.3-70b-versatile')


def _network_calls_allowed() -> bool:
    return 'test' not in {arg.lower() for arg in sys.argv}


def _build_open_port_prompt(port: int, service: str, state: str) -> str:
    return (
        "You are a cybersecurity assistant. Explain the finding in simple Hinglish with technical accuracy.\n"
        f"Open port finding: port={port}, service={service or 'unknown'}, state={state or 'unknown'}.\n\n"
        "Return plain text with these exact sections:\n"
        "1) Kya Hai\n"
        "2) Kyu Open Aata Hai\n"
        "3) Security Impact\n"
        "4) Real-world Example\n"
        "5) Kaise Thik Kare\n"
        "Keep response practical and concise."
    )


def _build_vulnerability_prompt(title: str, category: str, port: int, recommendation: str) -> str:
    return (
        "You are a cybersecurity assistant. Explain this vulnerability finding in simple Hinglish with technical accuracy.\n"
        f"Finding title: {title}\n"
        f"Category: {category or 'General'}\n"
        f"Related port: {port}\n"
        f"Current recommendation: {recommendation or 'N/A'}\n\n"
        "Return plain text with these exact sections:\n"
        "1) Kya Vulnerability Hai\n"
        "2) Ye Kyu Hoti Hai\n"
        "3) Potential Impact\n"
        "4) Attack Example\n"
        "5) Remediation Steps\n"
        "Do not include markdown tables."
    )


def _call_gemini(prompt: str) -> str:
    api_key = os.getenv('GEMINI_API_KEY')
    if not api_key or genai is None:
        raise RuntimeError('Gemini not configured')

    genai.configure(api_key=api_key)
    model = genai.GenerativeModel(DEFAULT_GEMINI_MODEL)
    response = model.generate_content(prompt)
    text = getattr(response, 'text', '') or ''
    if not text.strip():
        raise RuntimeError('Gemini returned empty response')
    return text.strip()


def _call_groq(prompt: str) -> str:
    api_key = os.getenv('GROQ_API_KEY')
    if not api_key:
        raise RuntimeError('Groq not configured')

    payload = {
        'model': DEFAULT_GROQ_MODEL,
        'messages': [
            {'role': 'system', 'content': 'You are a practical cybersecurity explainer.'},
            {'role': 'user', 'content': prompt},
        ],
        'temperature': 0.3,
    }

    req = urllib.request.Request(
        url='https://api.groq.com/openai/v1/chat/completions',
        data=json.dumps(payload).encode('utf-8'),
        headers={
            'Authorization': f'Bearer {api_key}',
            'Content-Type': 'application/json',
        },
        method='POST',
    )

    try:
        with urllib.request.urlopen(req, timeout=20) as resp:
            body = resp.read().decode('utf-8')
    except urllib.error.URLError as exc:
        raise RuntimeError(f'Groq request failed: {exc}') from exc

    parsed = json.loads(body)
    choices = parsed.get('choices') or []
    if not choices:
        raise RuntimeError('Groq returned empty response')

    content = ((choices[0].get('message') or {}).get('content') or '').strip()
    if not content:
        raise RuntimeError('Groq returned empty message content')
    return content


def _local_port_fallback(port: int, service: str, state: str) -> str:
    info = get_static_description(port) or {}
    description = info.get('description', 'Service details not available.')
    usage = info.get('usage', 'Restrict exposure and monitor logs for suspicious activity.')
    return (
        f"Kya Hai:\nPort {port} ({service or 'unknown service'}) abhi {state or 'unknown'} state me detect hua.\n\n"
        f"Kyu Open Aata Hai:\nYe usually tab open hota hai jab service externally listen kar rahi ho.\n\n"
        f"Security Impact:\n{description}\n\n"
        "Real-world Example:\nAgar weak auth ya outdated service ho, attacker brute-force ya known exploit try kar sakta hai.\n\n"
        f"Kaise Thik Kare:\n{usage}"
    )


def _local_vuln_fallback(title: str, recommendation: str) -> str:
    return (
        f"Kya Vulnerability Hai:\n{title}\n\n"
        "Ye Kyu Hoti Hai:\nMisconfiguration, exposed management surface, ya missing hardening controls ki wajah se.\n\n"
        "Potential Impact:\nUnauthorized access, data exposure, ya service disruption ho sakta hai.\n\n"
        "Attack Example:\nAttacker internet se exposed endpoint scan karke exploit path identify karta hai.\n\n"
        f"Remediation Steps:\n{recommendation or 'Access restrict karo, patching karo, aur continuous monitoring enable karo.'}"
    )


def _query_with_fallback(prompt: str) -> Tuple[str, str]:
    if not _network_calls_allowed():
        raise RuntimeError('Network calls disabled during tests')

    errors = []
    try:
        return _call_gemini(prompt), 'gemini'
    except Exception as exc:
        errors.append(f'gemini: {exc}')

    try:
        return _call_groq(prompt), 'groq'
    except Exception as exc:
        errors.append(f'groq: {exc}')

    raise RuntimeError('; '.join(errors) if errors else 'No AI provider available')


@lru_cache(maxsize=1024)
def explain_open_port(port: int, service: str = '', state: str = '') -> Tuple[str, str]:
    prompt = _build_open_port_prompt(port, service, state)
    try:
        return _query_with_fallback(prompt)
    except Exception:
        return _local_port_fallback(port, service, state), 'local'


@lru_cache(maxsize=512)
def explain_vulnerability(title: str, category: str = '', port: int = 0, recommendation: str = '') -> Tuple[str, str]:
    prompt = _build_vulnerability_prompt(title, category, port, recommendation)
    try:
        return _query_with_fallback(prompt)
    except Exception:
        return _local_vuln_fallback(title, recommendation), 'local'
