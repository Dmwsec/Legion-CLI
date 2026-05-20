import pytest

import modules.metasploit_safe as msf


def test_validate_module_accepts_aux_scanner():
    assert msf._validate_module('auxiliary/scanner/http/title') == 'auxiliary/scanner/http/title'


def test_validate_module_rejects_shell_chars():
    with pytest.raises(ValueError, match='Invalid module name'):
        msf._validate_module('auxiliary/scanner/http/title;rm -rf /')


def test_msf_search_blocks_shell_terms():
    with pytest.raises(ValueError, match='blocked'):
        msf.msf_search('shell')


def test_msf_info_blocks_exploit_modules():
    with pytest.raises(ValueError, match='blocked'):
        msf.msf_info('exploit/linux/http/foo')


def test_msf_plan_aux_scanner_creates_pending_approval(monkeypatch, tmp_path):
    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr(msf, 'create_approval', lambda **kwargs: {'id': 'appr-1'})
    out = msf.msf_plan('auxiliary/scanner/http/title', 'example.com')
    assert out['status'] == 'pending_approval'
    assert out['approval_id'] == 'appr-1'


def test_msf_plan_exploit_returns_manual_guidance(monkeypatch, tmp_path):
    monkeypatch.chdir(tmp_path)
    called = {'v': False}

    def fake_approval(**kwargs):
        called['v'] = True
        return {'id': 'should-not'}

    monkeypatch.setattr(msf, 'create_approval', fake_approval)
    out = msf.msf_plan('exploit/linux/http/foo', 'example.com')
    assert out['status'] == 'manual_guidance'
    assert 'cannot auto-execute' in out['message']
    assert called['v'] is False


def test_msf_plan_rejects_unsafe_target(monkeypatch, tmp_path):
    monkeypatch.chdir(tmp_path)
    with pytest.raises(ValueError, match='Invalid target'):
        msf.msf_plan('auxiliary/scanner/http/title', 'example.com;rm -rf /')


def test_msf_plan_execute_refuses_non_aux_scanner():
    with pytest.raises(ValueError, match=r'Only auxiliary/scanner/\* modules may execute'):
        msf.msf_plan_execute('exploit/linux/http/foo', 'example.com', 'abc')


def test_msf_plan_execute_refuses_blocked_aux_scanner_term():
    with pytest.raises(ValueError, match='msf-plan-execute blocked'):
        msf.msf_plan_execute('auxiliary/scanner/http/shell_probe', 'example.com', 'abc')


def test_run_msfconsole_uses_passed_command(monkeypatch):
    seen = {}

    class Proc:
        returncode = 0
        stdout = 'ok'
        stderr = ''

    def fake_run(args, **kwargs):
        seen['args'] = args
        return Proc()

    monkeypatch.setattr(msf.subprocess, 'run', fake_run)
    out = msf._run_msfconsole('search ssl')
    assert seen['args'] == ['msfconsole', '-q', '-x', 'search ssl']
    assert "'search ssl'" in out['command']
