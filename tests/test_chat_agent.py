from agents.chat_agent import ChatAgent
import web.agent as web_agent


def test_recon_intent_detected(monkeypatch):
    monkeypatch.setattr(web_agent, 'model_parse', lambda message, context: {'intent': 'run_recon_pipeline', 'params': {}, 'explanation': 'Recon requested.', 'next_suggestions': []})
    agent = ChatAgent()
    out = agent.handle('run recon', 'example.com')
    assert out['intent'] == 'run_recon_pipeline'


def test_idor_intent_detected(monkeypatch):
    monkeypatch.setattr(web_agent, 'model_parse', lambda message, context: {'intent': 'generate_idor_plan', 'params': {}, 'explanation': 'IDOR requested.', 'next_suggestions': []})
    agent = ChatAgent()
    out = agent.handle('find idor', 'example.com')
    assert out['intent'] == 'generate_idor_plan'


def test_unknown_intent_returns_none_or_manual(monkeypatch):
    monkeypatch.setattr(web_agent, 'model_parse', lambda message, context: {'intent': 'none', 'params': {}, 'explanation': 'No command', 'next_suggestions': []})
    agent = ChatAgent()
    out = agent.handle('???', 'example.com')
    assert out['intent'] in {'none', 'manual'}


def test_secrets_are_masked():
    masked = web_agent._mask('Authorization: Bearer SECRET123 and api_key=ABCD1234TOKEN')
    assert '***MASKED***' in masked
    assert 'SECRET123' not in masked
