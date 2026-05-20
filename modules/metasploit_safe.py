import json
import re
import shlex
import shutil
import subprocess
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urlparse

from core.approvals import create_approval, get_approval
from core.safe_paths import safe_target_name


BLOCKED_TERMS = [
    'exploit/', 'payload/', 'post/', 'meterpreter', 'persistence', 'shell',
    'reverse_tcp', 'bind_tcp', 'brute', 'login',
]
SAFE_EXECUTABLE_PREFIXES = ('auxiliary/scanner/',)
SAFE_MODULE_RE = re.compile(r'^[A-Za-z0-9_./-]+$')
SAFE_QUERY_RE = re.compile(r'^[A-Za-z0-9_.:/ -]{1,120}$')
SAFE_TARGET_RE = re.compile(r'^[A-Za-z0-9_.:-]{1,253}$')


def _safe_target_dir(target: str) -> str:
    return safe_target_name(target)


def _normalize_target_host(target: str) -> str:
    raw = (target or '').strip()
    if not raw:
        raise ValueError('Target is required')

    parsed = urlparse(raw)
    candidate = parsed.netloc or parsed.path or raw
    candidate = candidate.split('/')[0].split('?')[0].split('#')[0]
    candidate = candidate.rsplit('@', 1)[-1]

    if candidate.startswith('[') and ']' in candidate:
        host = candidate[1:candidate.index(']')]
    else:
        host = candidate.split(':', 1)[0]

    host = host.strip().strip('.')
    if not host:
        raise ValueError('Target host is required')
    return host


def _blocked_reason(module_or_query: str) -> str | None:
    low = (module_or_query or '').strip().lower()
    for term in BLOCKED_TERMS:
        if term in low:
            return f'Blocked by policy term: {term}'
    return None


def _ensure_msfconsole_installed() -> None:
    if shutil.which('msfconsole') is None:
        raise ValueError('msfconsole is not installed or not in PATH')


def _validate_module(module: str) -> str:
    m = (module or '').strip()
    if not m:
        raise ValueError('Module is required')
    if not SAFE_MODULE_RE.fullmatch(m):
        raise ValueError('Invalid module name')
    return m


def _validate_query(query: str) -> str:
    q = (query or '').strip()
    if not q:
        raise ValueError('Query is required')
    if not SAFE_QUERY_RE.fullmatch(q):
        raise ValueError('Invalid query')
    return q


def _validate_target(target: str) -> str:
    t = _normalize_target_host(target)
    if not SAFE_TARGET_RE.fullmatch(t):
        raise ValueError('Invalid target')
    return t


def _run_msfconsole(command: str) -> dict:
    if any(ch in command for ch in ['\n', '\r', '\x00']):
        raise ValueError('Unsafe msfconsole command')
    proc = subprocess.run(
        ['msfconsole', '-q', '-x', command],
        text=True,
        capture_output=True,
        timeout=120,
        check=False,
    )
    return {
        'command': f'msfconsole -q -x {shlex.quote(command)}',
        'returncode': proc.returncode,
        'stdout': proc.stdout,
        'stderr': proc.stderr,
    }


def msf_search(query: str) -> dict:
    q = _validate_query(query)
    reason = _blocked_reason(q)
    if reason:
        raise ValueError(f'msf-search blocked. {reason}')
    _ensure_msfconsole_installed()
    return _run_msfconsole(f'search {q}; exit')


def msf_info(module: str) -> dict:
    m = _validate_module(module)
    reason = _blocked_reason(m)
    if reason:
        raise ValueError(f'msf-info blocked. {reason}')
    _ensure_msfconsole_installed()
    return _run_msfconsole(f'info {m}; exit')


def msf_plan(module: str, target: str, scope: str = 'scope.yaml') -> dict:
    m = _validate_module(module)
    t = _validate_target(target)
    low = m.lower()
    blocked_reason = _blocked_reason(m)
    aux_scanner = low.startswith(SAFE_EXECUTABLE_PREFIXES)
    executable_with_approval = aux_scanner and not blocked_reason

    plan = {
        'status': 'planned',
        'target': t,
        'scope': scope,
        'module': m,
        'approval_required': executable_with_approval,
        'executable_with_approval': executable_with_approval,
        'policy': {
            'search_info_allowed': True,
            'aux_scanner_requires_approval': True,
            'manual_approval_required': ['exploit/*', 'payload/*', 'post/*', 'meterpreter', 'persistence', 'shell', 'reverse_tcp', 'bind_tcp', 'brute', 'login'],
        },
        'execution': 'not-executed',
        'created_at': datetime.now(timezone.utc).isoformat(),
    }

    if blocked_reason or not aux_scanner:
        plan['status'] = 'manual_guidance'
        plan['message'] = 'Only auxiliary/scanner/* modules may execute. Non-auxiliary or blocked modules require manual guidance and cannot auto-execute from this flow.'
    elif executable_with_approval:
        approval = create_approval(
            project='legion-cli',
            target=t,
            agent='cli',
            action='metasploit-plan-execute',
            command_preview=f'msfconsole -q -x "use {m}; setg RHOSTS {t}; run; exit"',
            risk_level='manual',
            reason=f'Metasploit execution approval required for module: {m}',
        )
        plan['approval_id'] = approval['id']
        plan['status'] = 'pending_approval'
        plan['message'] = 'Approval required before any Metasploit module execution.'

    out_dir = Path('evidence') / _safe_target_dir(t) / 'ai-analysis'
    out_dir.mkdir(parents=True, exist_ok=True)
    safe_mod = re.sub(r'[^a-zA-Z0-9._-]+', '_', m).strip('_') or 'module'
    out_file = out_dir / f'metasploit_plan_{safe_mod}.json'
    out_file.write_text(json.dumps(plan, indent=2), encoding='utf-8')

    return {**plan, 'plan_file': str(out_file)}


def msf_plan_execute(module: str, target: str, approval_id: str, scope: str = 'scope.yaml') -> dict:
    m = _validate_module(module)
    t = _validate_target(target)
    low = m.lower()
    if not low.startswith(SAFE_EXECUTABLE_PREFIXES):
        raise ValueError('Only auxiliary/scanner/* modules may execute in this flow. Use manual guidance for non-auxiliary modules.')
    reason = _blocked_reason(m)
    if reason:
        raise ValueError(f'msf-plan-execute blocked. {reason}')

    if not (approval_id or '').strip():
        raise ValueError('approval_id is required for Metasploit execution')

    rec = get_approval(approval_id.strip())
    if not rec:
        raise ValueError(f'Approval not found: {approval_id}')
    if rec.get('status') != 'approved':
        raise ValueError(f'Approval {approval_id} status is {rec.get("status")}; expected approved')

    _ensure_msfconsole_installed()
    cmd = f'use {m}; setg RHOSTS {t}; run; exit'
    out = _run_msfconsole(cmd)
    out.update({'status': 'executed', 'target': t, 'scope': scope, 'module': m, 'approval_id': approval_id})
    return out
