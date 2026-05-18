from web.agent_safety import safety_for
from web.agent_tools import required_for, missing_params

from .base import BaseAgent


class ToolRouterAgent(BaseAgent):
    def __init__(self):
        super().__init__(name='Tool Router Agent', risk='safe', status='active')

    def route(self, tool: str, params: dict) -> dict:
        self.set_status('active', f'route {tool}')
        call = {
            'tool': tool,
            'params': params or {},
            'required_parameters': required_for(tool),
        }
        return {
            'tool_call': call,
            'risk': safety_for(call),
            'missing': missing_params(tool, params or {}) if tool != 'none' else [],
        }
