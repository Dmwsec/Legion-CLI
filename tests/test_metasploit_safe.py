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


def test_msf_search_requires_msfconsole(monkeypatch):
    monkeypatch.setattr(msf.shutil, 'which', lambda _: None)
    with pytest.raises(ValueError, match='msfconsole is not installed'):
        msf.msf_search('ssl')


def test_msf_plan_execute_exploit_cannot_run_in_auto_flow():
    with pytest.raises(ValueError, match=r'Only auxiliary/scanner/\* modules may execute'):
        msf.msf_plan_execute('exploit/linux/http/foo', 'example.com', 'abc')


def test_aux_scanner_requires_approval_id():
    with pytest.raises(ValueError, match='approval_id is required'):
        msf.msf_plan_execute('auxiliary/scanner/http/title', 'example.com', '')
