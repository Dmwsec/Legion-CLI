from modules.evidence_manager import init_evidence_tree, evidence_path

from .base import BaseAgent


class EvidenceAgent(BaseAgent):
    def __init__(self):
        super().__init__(name='Evidence Collector', risk='safe', status='active')

    def ensure_tree(self, target: str) -> dict:
        self.set_status('active', f'init evidence {target}')
        return {'target': target, 'path': str(init_evidence_tree(target))}

    def path(self, target: str, *parts: str) -> str:
        self.set_status('active', f'evidence path {target}')
        return str(evidence_path(target, *parts))
