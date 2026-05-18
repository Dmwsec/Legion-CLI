from core.scope import validate_scope

from .base import BaseAgent


class ScopeGuardAgent(BaseAgent):
    def __init__(self):
        super().__init__(name='Scope Guard', risk='safe', status='active')

    def validate(self, target: str, scope: str = 'scope.yaml') -> dict:
        self.set_status('active', f'validate {target}')
        validate_scope(target, scope)
        return {'ok': True, 'target': target, 'scope': scope}
