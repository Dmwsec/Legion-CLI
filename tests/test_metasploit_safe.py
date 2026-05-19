import pytest

import modules.metasploit_safe as msf


def test_exploit_module_blocked():
    with pytest.raises(ValueError, match='blocked'):
        msf.msf_info('exploit/linux/http/foo')


def test_payload_module_blocked():
    with pytest.raises(ValueError, match='blocked'):
        msf.msf_info('payload/linux/x64/meterpreter/reverse_tcp')


def test_post_module_blocked():
    with pytest.raises(ValueError, match='blocked'):
        msf.msf_info('post/multi/manage/shell_to_meterpreter')


def test_msf_search_builds_safe_command(monkeypatch):
    seen = {}

    def fake_run(cmd):
        seen['cmd'] = cmd
        return {'command': cmd, 'returncode': 0, 'stdout': '', 'stderr': ''}

    monkeypatch.setattr(msf, '_run_msfconsole', fake_run)
    monkeypatch.setattr(msf.shutil, 'which', lambda _: '/usr/bin/msfconsole')
    msf.msf_search('ssl')
    assert seen['cmd'] == 'search ssl'


def test_msf_info_builds_safe_command(monkeypatch):
    seen = {}

    def fake_run(cmd):
        seen['cmd'] = cmd
        return {'command': cmd, 'returncode': 0, 'stdout': '', 'stderr': ''}

    monkeypatch.setattr(msf, '_run_msfconsole', fake_run)
    monkeypatch.setattr(msf.shutil, 'which', lambda _: '/usr/bin/msfconsole')
    msf.msf_info('auxiliary/scanner/http/title')
    assert seen['cmd'] == 'info auxiliary/scanner/http/title'


def test_msf_plan_execute_exploit_cannot_run_without_approval():
    with pytest.raises(ValueError, match='Only auxiliary/scanner/'):
        msf.msf_plan_execute('exploit/linux/http/foo', 'example.com', '')


def test_aux_scanner_executes_without_approval(monkeypatch):
    monkeypatch.setattr(msf.shutil, 'which', lambda _: '/usr/bin/msfconsole')
    monkeypatch.setattr(msf, '_run_msfconsole', lambda cmd: {'command': cmd, 'returncode': 0, 'stdout': 'ok', 'stderr': ''})
    out = msf.msf_plan_execute('auxiliary/scanner/http/title', 'example.com', '')
    assert out['status'] == 'executed'
