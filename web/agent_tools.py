from pathlib import Path

from core.tools import get_tools_with_status
from core.report import create_report_from_evidence
from modules.graphql import graphql_check
from modules.idor import generate_idor_plan
from modules.js_analyzer import analyze_js_url
from modules.nuclei_safe import run_nuclei_safe
from modules.oauth import oauth_check
from modules.recon_pipeline import run_recon_pipeline
from modules.traffic_import import import_burp_xml, import_caido_json
from modules.traffic_summary import traffic_summary

REQUIRED_PARAMS = {
    'get_tool_status': [],
    'list_targets': [],
    'list_evidence': ['target'],
    'list_findings': ['target'],
    'run_recon_pipeline': ['target'],
    'analyze_js_url': ['target', 'url'],
    'run_nuclei_safe': ['target', 'urls_file'],
    'analyze_graphql': ['target', 'endpoint'],
    'check_oauth': ['target', 'url'],
    'import_burp': ['target', 'file'],
    'import_caido': ['target', 'file'],
    'generate_idor_plan': ['target', 'replay_file'],
    'generate_report_from_evidence': ['target', 'finding'],
    'traffic_summary': ['target'],
}


def required_for(tool: str) -> list[str]:
    return REQUIRED_PARAMS.get(tool, [])


def missing_params(tool: str, params: dict) -> list[str]:
    req = required_for(tool)
    return [k for k in req if not params.get(k)]


def list_targets():
    r = Path('evidence')
    return sorted([p.name for p in r.iterdir() if p.is_dir()]) if r.exists() else []


def list_evidence(target: str):
    b = Path('evidence') / target
    return sorted([str(p.relative_to(b)) for p in b.rglob('*') if p.is_file()]) if b.exists() else []


def list_findings(target: str):
    f = Path('evidence') / target / 'ai-analysis'
    return sorted([p.name for p in f.glob('*.json')]) if f.exists() else []


def dispatch(tool: str, params: dict):
    if tool not in REQUIRED_PARAMS:
        raise ValueError(f'Unknown tool: {tool}')

    handlers = {
        'get_tool_status': lambda: get_tools_with_status(),
        'list_targets': lambda: list_targets(),
        'list_evidence': lambda: list_evidence(params['target']),
        'list_findings': lambda: list_findings(params['target']),
        'run_recon_pipeline': lambda: run_recon_pipeline(params['target']),
        'analyze_js_url': lambda: analyze_js_url(params['target'], params['url'], ai_summary=False),
        'run_nuclei_safe': lambda: run_nuclei_safe(params['target'], params['urls_file']),
        'analyze_graphql': lambda: graphql_check(params['endpoint'], params['target']),
        'check_oauth': lambda: oauth_check(params['target'], params['url']),
        'import_burp': lambda: import_burp_xml(params['file'], target=params['target']),
        'import_caido': lambda: import_caido_json(params['file'], target=params['target']),
        'generate_idor_plan': lambda: generate_idor_plan(params['target'], params['replay_file']),
        'generate_report_from_evidence': lambda: {'report': create_report_from_evidence(params['finding'], params['target'])},
        'traffic_summary': lambda: traffic_summary(params['target']),
    }

    handler = handlers.get(tool)
    if handler is None:
        raise ValueError(f'Unknown tool: {tool}')
    return handler()
