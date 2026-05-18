import ipaddress
import json
import os
import re
import socket
from pathlib import Path
from urllib.parse import urlparse

import requests
from openai import OpenAI

from core.approval import require_approval
from modules.evidence_manager import evidence_path, init_evidence_tree
from storage.database import init_db, insert_endpoint

API_ROUTE_REGEX = re.compile(r'/(?:api|v\d+)[A-Za-z0-9_\-/{}]*')
URL_REGEX = re.compile(r'https?://[^\s"\'<>]+')
SOURCE_MAP_REGEX = re.compile(r'//# sourceMappingURL=.*')
FEATURE_FLAG_REGEX = re.compile(r'(?i)(?:feature|flag|toggle)[_A-Za-z0-9-]*\s*[:=]\s*(?:true|false|["\'][^"\']+["\'])')
TOKEN_REGEX = re.compile(r'(?i)(?:api[_-]?key|token|secret|bearer)["\'\s:=]+([A-Za-z0-9._-]{8,})')


def _mask(value: str) -> str:
    if len(value) <= 8:
        return '*' * len(value)
    return value[:4] + '*' * (len(value) - 8) + value[-4:]


def _cloud_urls(text: str) -> list[str]:
    return sorted({u for u in URL_REGEX.findall(text) if any(x in u for x in ['amazonaws.com', 'storage.googleapis.com', 'azure', 'cloudfront.net'])})


def _hidden_endpoints(text: str) -> list[str]:
    return sorted({m.group(0) for m in re.finditer(r'(?i)(?:internal|admin|private)[A-Za-z0-9_\-/]*', text)})


def _summarize_with_ai(snippet: str) -> str:
    if not os.getenv('OPENAI_API_KEY'):
        return 'AI summary unavailable: OPENAI_API_KEY not configured.'
    require_approval('Send JavaScript snippet to OpenAI for summary?', 'approval')
    client = OpenAI()
    resp = client.responses.create(model='gpt-4.1-mini', input=f'Summarize security-relevant JavaScript findings:\n{snippet[:6000]}')
    return resp.output_text.strip()


def analyze_js_content(target: str, content: str, ai_summary: bool = False) -> dict:
    init_evidence_tree(target)
    init_db()

    routes = sorted(set(API_ROUTE_REGEX.findall(content)))
    hidden = _hidden_endpoints(content)
    features = sorted(set(FEATURE_FLAG_REGEX.findall(content)))
    source_maps = sorted(set(SOURCE_MAP_REGEX.findall(content)))
    clouds = _cloud_urls(content)
    raw_tokens = sorted(set(TOKEN_REGEX.findall(content)))
    masked_tokens = [_mask(t) for t in raw_tokens]

    for endpoint in routes + clouds:
        insert_endpoint(target=target, endpoint=endpoint, source='js-analyzer')

    findings = {
        'target': target,
        'api_routes': routes,
        'hidden_endpoints': hidden,
        'feature_flags': features,
        'source_maps': source_maps,
        'cloud_urls': clouds,
        'possible_tokens_masked': masked_tokens,
    }

    if ai_summary:
        findings['ai_summary'] = _summarize_with_ai(content)

    out = evidence_path(target, 'ai-analysis', 'js_findings.json')
    out.write_text(json.dumps(findings, indent=2))
    return {'target': target, 'output': str(out), 'routes': len(routes), 'tokens': len(masked_tokens)}


def _validate_public_http_url(url: str) -> str:
    parsed = urlparse(url)
    if parsed.scheme not in ('http', 'https'):
        raise ValueError('Invalid URL scheme. Only http and https are allowed.')
    if not parsed.hostname:
        raise ValueError('Invalid URL: hostname is required.')

    try:
        addr_info = socket.getaddrinfo(parsed.hostname, parsed.port or (443 if parsed.scheme == 'https' else 80))
    except socket.gaierror as e:
        raise ValueError(f'Could not resolve hostname: {parsed.hostname}') from e

    for info in addr_info:
        ip_str = info[4][0]
        ip_obj = ipaddress.ip_address(ip_str)
        if (
            ip_obj.is_private
            or ip_obj.is_loopback
            or ip_obj.is_link_local
            or ip_obj.is_multicast
            or ip_obj.is_reserved
            or ip_obj.is_unspecified
        ):
            raise ValueError('URL resolves to a non-public IP address, which is not allowed.')

    return url


def analyze_js_url(target: str, url: str, ai_summary: bool = False) -> dict:
    safe_url = _validate_public_http_url(url)
    content = requests.get(safe_url, timeout=30).text
    return analyze_js_content(target, content, ai_summary=ai_summary)


def analyze_js_file(target: str, file_path: str, ai_summary: bool = False) -> dict:
    content = Path(file_path).read_text(errors='ignore')
    return analyze_js_content(target, content, ai_summary=ai_summary)
