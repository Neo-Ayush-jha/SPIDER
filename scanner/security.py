import ipaddress
import socket
from urllib.parse import urlparse

from .port_info import PORT_DETAILS


SCAN_PRESETS = {
    'quick': {'label': 'Quick Recon', 'ports': '1-1024'},
    'web': {'label': 'Web Surface', 'ports': '80,81,443,591,8000,8008,8080,8081,8088,8443,8888'},
    'remote': {'label': 'Remote Access', 'ports': '21,22,23,25,53,110,135,139,143,389,443,445,465,587,993,995,1723,3306,3389,5432,5900'},
    'database': {'label': 'Database Exposure', 'ports': '1433,1521,3306,5432,6379,8086,9042,9200,27017'},
    'custom': {'label': 'Custom', 'ports': '1-1024'},
}

RISK_SCORES = {
    'critical': 25,
    'high': 15,
    'medium': 8,
    'low': 3,
    'unknown': 5,
}

PORT_CATEGORIES = {
    21: 'Credential Exposure',
    22: 'Remote Administration',
    23: 'Legacy Remote Access',
    25: 'Mail Infrastructure',
    53: 'Network Core Service',
    80: 'Web Service',
    110: 'Mail Infrastructure',
    139: 'Windows File Sharing',
    143: 'Mail Infrastructure',
    389: 'Identity Service',
    443: 'Web Service',
    445: 'Windows File Sharing',
    1433: 'Database Service',
    3306: 'Database Service',
    3389: 'Remote Administration',
    5432: 'Database Service',
    5900: 'Remote Administration',
    8080: 'Web Service',
    8443: 'Web Service',
}


def sanitize_target(target):
    raw_value = (target or '').strip()
    if not raw_value:
        raise ValueError('Target required.')

    parsed = urlparse(raw_value if '://' in raw_value else f'http://{raw_value}')
    hostname = parsed.hostname or raw_value.split('/')[0]
    hostname = hostname.strip().rstrip('.')
    if not hostname:
        raise ValueError('Could not extract a valid host from the target.')

    if len(hostname) > 253:
        raise ValueError('Target is too long.')

    try:
        ipaddress.ip_address(hostname)
        return raw_value, hostname
    except ValueError:
        pass

    allowed = set('abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-.')
    if any(char not in allowed for char in hostname):
        raise ValueError('Target contains invalid characters.')

    if '..' in hostname or hostname.startswith('-') or hostname.endswith('-'):
        raise ValueError('Target is not a valid hostname.')

    return raw_value, hostname.lower()


def resolve_target(hostname):
    try:
        return socket.gethostbyname(hostname)
    except OSError:
        return None


def normalize_port_input(ports):
    value = (ports or '').strip() or '1-1024'
    chunks = [chunk.strip() for chunk in value.split(',') if chunk.strip()]
    if not chunks:
        raise ValueError('Port selection cannot be empty.')

    normalized = []
    expanded_total = 0

    for chunk in chunks:
        if '-' in chunk:
            start_str, end_str = [part.strip() for part in chunk.split('-', 1)]
            if not start_str.isdigit() or not end_str.isdigit():
                raise ValueError(f"Invalid port range '{chunk}'.")
            start, end = int(start_str), int(end_str)
            if start > end:
                raise ValueError(f"Invalid port range '{chunk}'.")
            if start < 1 or end > 65535:
                raise ValueError('Ports must be between 1 and 65535.')
            expanded_total += (end - start) + 1
            normalized.append(f'{start}-{end}')
        else:
            if not chunk.isdigit():
                raise ValueError(f"Invalid port '{chunk}'.")
            port = int(chunk)
            if port < 1 or port > 65535:
                raise ValueError('Ports must be between 1 and 65535.')
            expanded_total += 1
            normalized.append(str(port))

    if expanded_total > 5000:
        raise ValueError('Requested port set is too large. Keep it under 5000 ports per scan.')

    return ','.join(normalized)


def get_port_metadata(port):
    info = PORT_DETAILS.get(port, {})
    risk_level = info.get('risk_level', 'Unknown')
    primary_risk = risk_level.split('/')[0].strip().lower()

    return {
        'name': info.get('name', 'Unknown Port'),
        'description': info.get('description', 'No detailed information found for this port.'),
        'usage': info.get('usage', 'Review the service and restrict access to trusted networks.'),
        'risk_level': risk_level,
        'risk_bucket': primary_risk if primary_risk in RISK_SCORES else 'unknown',
        'category': PORT_CATEGORIES.get(port, 'General Service'),
    }


def analyze_scan_results(results):
    summary = {
        'open_ports': 0,
        'filtered_ports': 0,
        'closed_ports': 0,
        'high_risk_ports': 0,
        'risk_score': 0,
        'top_exposures': [],
        'recommendations': [],
    }

    findings = []
    seen_recommendations = set()

    for result in results:
        state = (result.get('state') or '').lower()
        port = result.get('port')
        metadata = get_port_metadata(port)
        for key, value in metadata.items():
            if not result.get(key):
                result[key] = value

        if state == 'open':
            summary['open_ports'] += 1
            summary['risk_score'] += RISK_SCORES[metadata['risk_bucket']]
            if metadata['risk_bucket'] in {'critical', 'high'}:
                summary['high_risk_ports'] += 1
                findings.append({
                    'severity': metadata['risk_level'],
                    'port': port,
                    'title': f"{metadata['name']} exposed on port {port}",
                    'category': metadata['category'],
                    'recommendation': metadata['usage'],
                })
            if metadata['usage'] not in seen_recommendations:
                seen_recommendations.add(metadata['usage'])
                summary['recommendations'].append(metadata['usage'])
        elif state == 'filtered':
            summary['filtered_ports'] += 1
        elif state == 'closed':
            summary['closed_ports'] += 1

    open_ports = {result['port'] for result in results if (result.get('state') or '').lower() == 'open'}
    if 80 in open_ports and 443 not in open_ports:
        findings.append({
            'severity': 'High',
            'port': 80,
            'title': 'HTTP is exposed without HTTPS',
            'category': 'Web Service',
            'recommendation': 'Redirect HTTP to HTTPS and disable plaintext administration surfaces.',
        })

    if {22, 3389}.issubset(open_ports):
        findings.append({
            'severity': 'High',
            'port': 3389,
            'title': 'Multiple remote administration channels are exposed',
            'category': 'Remote Administration',
            'recommendation': 'Restrict remote access ports behind a VPN, IP allowlist, or bastion host.',
        })

    summary['risk_score'] = min(summary['risk_score'], 100)
    findings.sort(key=lambda item: (RISK_SCORES.get(item['severity'].split('/')[0].lower(), 0), item['port']), reverse=True)
    summary['top_exposures'] = findings[:5]
    summary['recommendations'] = summary['recommendations'][:5]
    return summary, findings
