import json
from pathlib import Path

from core.runner import run_command, tool_exists, write_output
from core.approvals import create_approval
from modules.evidence_manager import evidence_path, init_evidence_tree
from storage.database import init_db, insert_recon_artifact


DEFAULT_TAGS = 'exposure,misconfig,takeover,panel,headers,tech'
DEFAULT_EXCLUDE_TAGS = 'rce,dos,intrusive,bruteforce,fuzz,exploit'
DEFAULT_SEVERITY = 'info,low,medium'
BLOCKED_TAG_TERMS = {'rce', 'dos', 'intrusive', 'bruteforce', 'fuzz', 'exploit'}


def _csv_set(value: str) -> set[str]:
    return {x.strip().lower() for x in (value or '').split(',') if x.strip()}


def run_nuclei_safe(target: str, urls_file: str, tags: str = DEFAULT_TAGS, exclude_tags: str = DEFAULT_EXCLUDE_TAGS, severity: str = DEFAULT_SEVERITY) -> dict:
    if not tool_exists('nuclei'):
        return {'target': target, 'error': 'nuclei not installed'}
    if not Path(urls_file).exists():
        return {'target': target, 'error': f'urls_file not found: {urls_file}'}

    requested_tags = _csv_set(tags)
    blocked_requested = sorted(requested_tags & BLOCKED_TAG_TERMS)
    if blocked_requested:
        req = create_approval(
            project='legion-cli',
            target=target,
            agent='nuclei-safe',
            action='run_nuclei_with_blocked_tags',
            command_preview=f'nuclei -l {urls_file} -tags {tags}',
            risk_level='approval',
            reason=f'Blocked nuclei tags requested: {",".join(blocked_requested)}',
        )
        return {
            'target': target,
            'status': 'approval_required',
            'message': f'Blocked tags requested: {", ".join(blocked_requested)}. Review approval before any risky scan.',
            'approval_id': req['id'],
        }

    init_evidence_tree(target)
    init_db()
    out = evidence_path(target, 'ai-analysis', 'nuclei_safe.jsonl')
    parsed_out = evidence_path(target, 'ai-analysis', 'nuclei_findings.json')

    command = (
        f'nuclei -l {urls_file} '
        f'-tags {tags} '
        f'-exclude-tags {exclude_tags} '
        f'-severity {severity} '
        '-jsonl -silent'
    )
    result = run_command(command, risk='safe')
    raw = result.get('stdout', '') or ''
    write_output(str(out), raw)
    findings = []
    for line in raw.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            findings.append(json.loads(line))
        except Exception:
            continue
    write_output(str(parsed_out), json.dumps(findings, indent=2))
    insert_recon_artifact(target, 'scanner', 'nuclei-safe', str(out), len((result.get('stdout', '') or '').splitlines()))
    return {'target': target, 'output': str(out), 'parsed_output': str(parsed_out), 'findings_count': len(findings), 'returncode': result.get('returncode')}
