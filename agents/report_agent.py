from core.report import create_report, create_report_from_evidence

from .base import BaseAgent


class ReportAgent(BaseAgent):
    def __init__(self):
        super().__init__(name='Report Agent', risk='safe', status='active')

    def build(self, finding: str, target: str, ai_draft: bool = False, evidence: str = ''):
        self.set_status('active', f'report {finding}')
        return create_report(finding, target, ai_draft=ai_draft, evidence=evidence)

    def build_from_evidence(self, finding: str, target: str) -> str:
        self.set_status('active', f'report-auto {finding}')
        return create_report_from_evidence(finding, target)
