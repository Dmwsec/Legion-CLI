from agents.scope_guard_agent import ScopeGuardAgent
from agents.tool_router_agent import ToolRouterAgent

from .base import BaseAgent


class CommanderAgent(BaseAgent):
    def __init__(self):
        super().__init__(name='Commander Agent', risk='safe', status='active')
        self.scope_guard = ScopeGuardAgent()
        self.router = ToolRouterAgent()

    def build_safe_plan(self, target: str, scope: str, intent: str, params: dict) -> dict:
        self.set_status('active', f'plan {intent}')
        self.scope_guard.validate(target, scope)
        routed = self.router.route(intent, {**(params or {}), 'target': target})
        return {
            'target': target,
            'scope': scope,
            'intent': intent,
            'tool_call': routed['tool_call'],
            'risk': routed['risk'],
            'missing': routed['missing'],
            'confirmation_required': routed['risk'] == 'approval',
        }
