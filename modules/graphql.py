import json
import socket
import ipaddress
from urllib.parse import urlparse

import requests

from modules.evidence_manager import evidence_path, init_evidence_tree

INTROSPECTION_QUERY = '{ __schema { queryType { name } mutationType { name } types { name } } }'


def _validate_outbound_url(endpoint: str) -> str:
    parsed = urlparse(endpoint)
    if parsed.scheme not in ('http', 'https'):
        raise ValueError('Only http/https endpoints are allowed')
    if not parsed.hostname:
        raise ValueError('Endpoint must include a valid hostname')

    try:
        addrinfo = socket.getaddrinfo(parsed.hostname, parsed.port or (443 if parsed.scheme == 'https' else 80))
    except socket.gaierror as exc:
        raise ValueError(f'Unable to resolve endpoint hostname: {exc}') from exc

    for info in addrinfo:
        ip_str = info[4][0]
        ip_obj = ipaddress.ip_address(ip_str)
        if (
            ip_obj.is_private
            or ip_obj.is_loopback
            or ip_obj.is_link_local
            or ip_obj.is_reserved
            or ip_obj.is_multicast
            or ip_obj.is_unspecified
        ):
            raise ValueError('Endpoint resolves to a non-public IP address')

    return endpoint


def graphql_check(endpoint: str, target: str) -> dict:
    init_evidence_tree(target)
    summary = {'endpoint': endpoint, 'introspection': 'unknown', 'status': None}

    try:
        safe_endpoint = _validate_outbound_url(endpoint)
        resp = requests.post(safe_endpoint, json={'query': INTROSPECTION_QUERY}, timeout=20)
        summary['status'] = resp.status_code
        data = resp.json() if resp.headers.get('content-type', '').startswith('application/json') else {}
        summary['introspection'] = 'enabled' if isinstance(data, dict) and data.get('data', {}).get('__schema') else 'disabled_or_filtered'
        summary['response_sample'] = (resp.text or '')[:500]
    except Exception as exc:
        summary['error'] = str(exc)

    out = evidence_path(target, 'ai-analysis', 'graphql_analysis.json')
    out.write_text(json.dumps(summary, indent=2))
    return {'target': target, 'output': str(out), 'status': summary.get('status')}
