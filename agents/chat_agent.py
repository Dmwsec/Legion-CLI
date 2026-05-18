from web.agent import model_parse

from .base import BaseAgent
from .commander_agent import CommanderAgent


class ChatAgent(BaseAgent):
    def __init__(self):
        super().__init__(name='Chat Agent', risk='safe', status='active')
        self.commander = CommanderAgent()

    def handle(self, message: str, target: str, scope: str = 'scope.yaml') -> dict:
        self.set_status('active', 'chat-parse')
        parsed = model_parse(message, {'target': target, 'scope': scope})
        intent = parsed.get('intent', 'none')
        params = parsed.get('params', {}) or {}
        plan = self.commander.build_safe_plan(target, scope, intent, params)
        return {
            'assistant_message': parsed.get('explanation', 'Ready.'),
            'intent': intent,
            'params': params,
            'plan': plan,
            'next_suggestions': parsed.get('next_suggestions', []),
        }
