from modules.metasploit_safe import msf_search, msf_info, msf_plan

from .base import BaseAgent


class MetasploitAgent(BaseAgent):
    def __init__(self):
        super().__init__(name='Metasploit Agent', risk='manual', status='manual')

    def search(self, query: str) -> dict:
        self.set_status('manual', 'msf-search')
        return msf_search(query)

    def info(self, module: str) -> dict:
        self.set_status('manual', 'msf-info')
        return msf_info(module)

    def plan(self, module: str, target: str, scope: str = 'scope.yaml') -> dict:
        self.set_status('manual', 'msf-plan')
        return msf_plan(module, target, scope=scope)
