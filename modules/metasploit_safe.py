import json
import re
import shlex
import subprocess
from datetime import datetime, timezone
from pathlib import Path

from core.approvals import create_approval, get_approval


BLOCKED_TERMS = [
    'exploit/', 'payload/', 'post/', 'meterpreter', 'persistence', 'shell',
    'reverse_tcp', 'bind_tcp', 'brute', 'login',
]


def _blocked_reason(module_or_query: str) -> str | None:
    low = (module_or_query or '').strip().lower()
    for term in BLOCKED_TERMS:
        if term in low:
            return f'Blocked by policy term: {term}'
    return None


def _run_msfconsole(command: str) -> dict:
    proc = subprocess.run(
        ['msfconsole', '-q', '-x', f'{command}; exit'],
        text=True,
        capture_output=True,
        timeout=120,
    )
    return {
        'command': f'msfconsole -q -x {shlex.quote(command + "; exit")}',
        'returncode': proc.returncode,
        'stdout': proc.stdout,
        'stderr': proc.stderr,
    }


def msf_search(query: str) -> dict:
    reason = _blocked_reason(query)
    if reason:
        raise ValueError(f'msf-search blocked. {reason}')
    if not (query or '').strip():
        raise ValueError('Query is required for msf-search')
    return _run_msfconsole(f'search {query.strip()}')


def msf_info(module: str) -> dict:
    reason = _blocked_reason(module)
    if reason:
        raise ValueError(f'msf-info blocked. {reason}')
    m = (module or '').strip()
    if not m:
        raise ValueError('Module is required for msf-info')
    return _run_msfconsole(f'info {m}')


def msf_plan(module: str, target: str, scope: str = 'scope.yaml') -> dict:
    m = (module or '').strip()
    if not m:
        raise ValueError('Module is required for msf-plan')

    low = m.lower()
    blocked_reason = _blocked_reason(m)
    approval_required = bool(blocked_reason) or low.startswith('auxiliary/scanner/')
    plan = {
        'status': 'planned',
        'target': target,
        'scope': scope,
        'module': m,
        'approval_required': approval_required,
        'policy': {
            'search_info_allowed': True,
            'aux_scanner_allowed_with_approval_only': True,
            'never_execute': ['exploit/*', 'payload/*', 'post/*', 'shell payloads', 'credential brute force', 'persistence'],
        },
        'execution': 'not-executed',
        'created_at': datetime.now(timezone.utc).isoformat(),
    }

    if approval_required:
        approval = create_approval(
            project='legion-cli',
            target=target,
            agent='cli',
            action='metasploit-plan-execute',
            command_preview=f'msfconsole -q -x "use {m}; setg RHOSTS {target}; run; exit"',
            risk_level='manual',
            reason=f'Metasploit execution approval required for module: {m}',
        )
        plan['approval_id'] = approval['id']
        plan['status'] = 'pending_approval'
        plan['message'] = 'Approval required before any Metasploit module execution.'

    out_dir = Path('evidence') / target / 'ai-analysis'
    out_dir.mkdir(parents=True, exist_ok=True)
    safe_mod = re.sub(r'[^a-zA-Z0-9._-]+', '_', m).strip('_') or 'module'
    out_file = out_dir / f'metasploit_plan_{safe_mod}.json'
    out_file.write_text(json.dumps(plan, indent=2), encoding='utf-8')

    return {**plan, 'plan_file': str(out_file)}


def msf_plan_execute(module: str, target: str, approval_id: str, scope: str = 'scope.yaml') -> dict:
    m = (module or '').strip()
    t = (target or '').strip()
    if not m:
        raise ValueError('Module is required for msf-plan')
    if not t:
        raise ValueError('Target is required for msf-plan')
    if not (approval_id or '').strip():
        raise ValueError('approval_id is required for module execution')

    rec = get_approval(approval_id.strip())
    if not rec:
        raise ValueError(f'Approval not found: {approval_id}')
    if rec.get('status') != 'approved':
        raise ValueError(f'Approval {approval_id} status is {rec.get("status")}; expected approved')

    cmd = f'use {m}; setg RHOSTS {t}; run'
    out = _run_msfconsole(cmd)
    out.update({'status': 'executed', 'target': t, 'scope': scope, 'module': m, 'approval_id': approval_id})
    return out
