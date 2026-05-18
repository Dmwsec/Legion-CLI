import json
from datetime import datetime, timezone
from pathlib import Path
from uuid import uuid4

ROOT = Path('data/approvals')
ROOT.mkdir(parents=True, exist_ok=True)

VALID_STATUS = {'pending', 'approved', 'denied'}


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _path(approval_id: str) -> Path:
    return ROOT / f'{approval_id}.json'


def create_approval(project: str, target: str, agent: str, action: str, command_preview: str, risk_level: str, reason: str) -> dict:
    aid = str(uuid4())
    data = {
        'id': aid,
        'created_at': _now(),
        'project': project or '',
        'target': target or '',
        'agent': agent or '',
        'action': action or '',
        'command_preview': command_preview or '',
        'risk_level': risk_level or 'approval',
        'reason': reason or '',
        'status': 'pending',
    }
    _path(aid).write_text(json.dumps(data, indent=2), encoding='utf-8')
    return data


def get_approval(approval_id: str) -> dict | None:
    p = _path(approval_id)
    if not p.exists():
        return None
    try:
        return json.loads(p.read_text(encoding='utf-8'))
    except Exception:
        return None


def set_status(approval_id: str, status: str) -> dict:
    if status not in VALID_STATUS:
        raise ValueError(f'Invalid status: {status}')
    rec = get_approval(approval_id)
    if not rec:
        raise FileNotFoundError(f'Approval not found: {approval_id}')
    rec['status'] = status
    rec['updated_at'] = _now()
    _path(approval_id).write_text(json.dumps(rec, indent=2), encoding='utf-8')
    return rec


def list_approvals() -> list[dict]:
    rows = []
    for p in sorted(ROOT.glob('*.json')):
        try:
            rows.append(json.loads(p.read_text(encoding='utf-8')))
        except Exception:
            continue
    rows.sort(key=lambda x: x.get('created_at', ''), reverse=True)
    return rows


def approve(approval_id: str) -> dict:
    return set_status(approval_id, 'approved')


def deny(approval_id: str) -> dict:
    return set_status(approval_id, 'denied')
