import pytest
from fastapi import HTTPException

import web.agent_tools as agent_tools
from web.app import chat_confirm
from web.schemas import ChatConfirmRequest


def test_unknown_dispatch_tool_raises_clean_error():
    with pytest.raises(ValueError, match='Unknown tool: nope'):
        agent_tools.dispatch('nope', {})


def test_chat_confirm_blocks_manual_tool(monkeypatch):
    monkeypatch.setattr('web.app.load_session', lambda sid: ('s1', {'pending_confirmation': {'tool': 'metasploit_agent', 'params': {}, 'approval_id': None}}))

    with pytest.raises(HTTPException) as exc:
        chat_confirm(ChatConfirmRequest(session_id='s1'))

    assert exc.value.status_code == 403
