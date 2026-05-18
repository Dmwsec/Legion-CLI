from pathlib import Path

import modules.nuclei_safe as ns


def test_unsafe_tags_rejected(monkeypatch, tmp_path):
    urls = tmp_path / 'urls.txt'
    urls.write_text('https://example.com\n')

    monkeypatch.setattr(ns, 'tool_exists', lambda _: True)

    created = {}

    def fake_create(**kwargs):
        created.update(kwargs)
        return {'id': 'approval-123'}

    monkeypatch.setattr(ns, 'create_approval', fake_create)

    out = ns.run_nuclei_safe('example.com', str(urls), tags='exposure,rce')
    assert out['status'] == 'approval_required'
    assert out['approval_id'] == 'approval-123'
    assert 'rce' in created.get('reason', '').lower()


def test_safe_command_includes_exclude_tags(monkeypatch, tmp_path):
    urls = tmp_path / 'urls.txt'
    urls.write_text('https://example.com\n')

    monkeypatch.setattr(ns, 'tool_exists', lambda _: True)
    monkeypatch.setattr(ns, 'init_evidence_tree', lambda target: None)
    monkeypatch.setattr(ns, 'init_db', lambda: None)
    monkeypatch.setattr(ns, 'insert_recon_artifact', lambda *a, **k: None)

    out_jsonl = tmp_path / 'nuclei_safe.jsonl'
    out_findings = tmp_path / 'nuclei_findings.json'

    def fake_evidence_path(target, group, name):
        return out_jsonl if name.endswith('.jsonl') else out_findings

    monkeypatch.setattr(ns, 'evidence_path', fake_evidence_path)

    seen = {}

    def fake_run(command, risk='safe', cwd=None):
        seen['command'] = command
        return {'command': command, 'returncode': 0, 'stdout': '', 'stderr': ''}

    monkeypatch.setattr(ns, 'run_command', fake_run)

    out = ns.run_nuclei_safe('example.com', str(urls))
    assert out['returncode'] == 0
    assert '-exclude-tags rce,dos,intrusive,bruteforce,fuzz,exploit' in seen['command']
