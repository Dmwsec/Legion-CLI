import agents.chat_agent as chat_mod
from agents.chat_agent import ChatAgent
import web.agent as web_agent


def _scope_file(tmp_path):
    p = tmp_path / 'scope.yaml'
    p.write_text('allowed_domains:\n  - example.com\nout_of_scope: []\n')
    return str(p)


def test_recon_intent_detected(monkeypatch, tmp_path):
    monkeypatch.setattr(chat_mod, 'model_parse', lambda message, context: {'intent': 'run_recon_pipeline', 'params': {}, 'explanation': 'Recon requested.', 'next_suggestions': []})
    agent = ChatAgent()
    out = agent.handle('run recon', 'example.com', scope=_scope_file(tmp_path))
    assert out['intent'] == 'run_recon_pipeline'


def test_idor_intent_detected(monkeypatch, tmp_path):
    monkeypatch.setattr(chat_mod, 'model_parse', lambda message, context: {'intent': 'generate_idor_plan', 'params': {}, 'explanation': 'IDOR requested.', 'next_suggestions': []})
    agent = ChatAgent()
    out = agent.handle('find idor', 'example.com', scope=_scope_file(tmp_path))
    assert out['intent'] == 'generate_idor_plan'


def test_unknown_intent_returns_none_or_manual(monkeypatch, tmp_path):
    monkeypatch.setattr(chat_mod, 'model_parse', lambda message, context: {'intent': 'none', 'params': {}, 'explanation': 'No command', 'next_suggestions': []})
    agent = ChatAgent()
    out = agent.handle('???', 'example.com', scope=_scope_file(tmp_path))
    assert out['intent'] in {'none', 'manual'}


def test_secrets_are_masked():
    masked = web_agent._mask('Authorization: Bearer SECRET123 and api_key=ABCD1234TOKEN')
    assert '***MASKED***' in masked
    assert 'SECRET123' not in masked
