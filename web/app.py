from pathlib import Path
import json
from fastapi import FastAPI, HTTPException
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles
from core.scope import validate_scope
from core.tools import get_tools_with_status
from modules.graphql import graphql_check
from modules.idor import generate_idor_plan
from modules.js_analyzer import analyze_js_url
from modules.nuclei_safe import run_nuclei_safe
from modules.oauth import oauth_check
from modules.recon_pipeline import run_recon_pipeline
from core.report import create_report_from_evidence
from modules.scope_builder import create_scope_from_text, use_scope, list_scopes
from modules.replay_engine import replay_diff
from modules.finding_ranker import rank_findings
from web.agent import model_parse
from web.schemas import *
from web.agent_memory import load_session, save_session
from web.agent_safety import safety_for
from web.agent_tools import dispatch, missing_params, required_for
from core.approvals import create_approval, list_approvals, approve as approve_request, deny as deny_request, get_approval

app = FastAPI(title='Legion Dashboard API')
static_dir = Path(__file__).parent / 'static'
app.mount('/static', StaticFiles(directory=static_dir), name='static')
@app.get('/')
def index(): return FileResponse(static_dir / 'index.html')
@app.get('/api/health')
def health(): return {'status': 'ok'}
@app.get('/api/tools')
def tools(): return {'tools': get_tools_with_status()}
@app.get('/api/targets')
def targets():
    r = Path('evidence'); return {'targets': sorted([p.name for p in r.iterdir() if p.is_dir()]) if r.exists() else []}
@app.get('/api/evidence/{target}')
def evidence(target: str):
    b = Path('evidence') / target; return {'files': sorted([str(p.relative_to(b)) for p in b.rglob('*') if p.is_file()]) if b.exists() else []}
@app.get('/api/findings/{target}')
def findings(target: str):
    f = Path('evidence') / target / 'ai-analysis'; return {'findings': sorted([p.name for p in f.glob('*.json')]) if f.exists() else []}

@app.get('/api/agents/status')
def agents_status():
    return [
        {'name': 'Scope Guard', 'status': 'active', 'risk': 'safe'},
        {'name': 'Recon Agent', 'status': 'active', 'risk': 'safe'},
        {'name': 'HTTP Probe Agent', 'status': 'active', 'risk': 'safe'},
        {'name': 'JS Intelligence Agent', 'status': 'active', 'risk': 'safe'},
        {'name': 'API Mapper Agent', 'status': 'active', 'risk': 'safe'},
        {'name': 'Auth Diff Agent', 'status': 'idle', 'risk': 'approval'},
        {'name': 'IDOR Hunter Agent', 'status': 'idle', 'risk': 'approval'},
        {'name': 'Nuclei Safe Agent', 'status': 'idle', 'risk': 'approval'},
        {'name': 'Metasploit Agent', 'status': 'manual', 'risk': 'manual'},
        {'name': 'Race Condition Agent', 'status': 'manual', 'risk': 'manual'},
        {'name': 'Cloud & Secrets Agent', 'status': 'active', 'risk': 'safe'},
        {'name': 'Evidence Collector', 'status': 'active', 'risk': 'safe'},
        {'name': 'False Positive Killer', 'status': 'active', 'risk': 'safe'},
        {'name': 'Risk Ranker Agent', 'status': 'active', 'risk': 'safe'},
        {'name': 'Report Agent', 'status': 'active', 'risk': 'safe'},
        {'name': 'Retest Agent', 'status': 'idle', 'risk': 'safe'},
    ]

@app.get('/api/approvals')
def approvals():
    return {'approvals': list_approvals()}

@app.post('/api/approvals/{approval_id}/approve')
def approvals_approve(approval_id: str):
    try:
        return approve_request(approval_id)
    except FileNotFoundError as e:
        raise HTTPException(status_code=404, detail=str(e))

@app.post('/api/approvals/{approval_id}/deny')
def approvals_deny(approval_id: str):
    try:
        return deny_request(approval_id)
    except FileNotFoundError as e:
        raise HTTPException(status_code=404, detail=str(e))

@app.get('/api/dashboard/{target}')
def dashboard_summary(target: str):
    evidence_root = Path('evidence').resolve()
    base = (evidence_root / target).resolve()
    try:
        base.relative_to(evidence_root)
    except ValueError:
        raise HTTPException(status_code=400, detail='Invalid target path')
    files = [p for p in base.rglob('*') if p.is_file()] if base.exists() else []
    evidence_items = len(files)

    urls_file = base / 'recon' / 'urls.txt'
    urls = []
    if urls_file.exists():
        try:
            urls = [ln.strip() for ln in urls_file.read_text(errors='ignore').splitlines() if ln.strip()]
        except Exception:
            urls = []

    ai_dir = base / 'ai-analysis'
    finding_files = sorted(ai_dir.glob('*.json')) if ai_dir.exists() else []
    severity_counts = {'critical': 0, 'high': 0, 'medium': 0, 'low': 0, 'info': 0}
    top_findings = []
    recent_findings = []
    for fp in finding_files:
        item = {'name': fp.name, 'severity': 'info'}
        try:
            data = json.loads(fp.read_text(errors='ignore'))
            if isinstance(data, dict):
                sev = str(data.get('severity', 'info')).lower()
                if sev not in severity_counts:
                    sev = 'info'
                item = {
                    'name': data.get('title') or data.get('name') or fp.stem,
                    'severity': sev,
                    'category': data.get('category', ''),
                    'file': fp.name,
                }
            elif isinstance(data, list):
                item['name'] = fp.stem
        except Exception:
            pass
        severity_counts[item['severity']] += 1
        recent_findings.append(item)

    sev_weights = {'critical': 5, 'high': 4, 'medium': 3, 'low': 2, 'info': 1}
    top_findings = sorted(recent_findings, key=lambda x: sev_weights.get(x.get('severity', 'info'), 1), reverse=True)[:5]
    recent_findings = list(reversed(recent_findings))[:5]

    tooling_status = get_tools_with_status()
    agents_online = sum(1 for t in tooling_status if t.get('installed'))
    risk_score = min(100, severity_counts['critical'] * 25 + severity_counts['high'] * 12 + severity_counts['medium'] * 6 + severity_counts['low'] * 2)

    live_requests = []
    recent_activity = []
    attack_surface = urls[:50]
    for u in urls[:6]:
        live_requests.append({'method': 'GET', 'url': u, 'status': 200, 'time': '-'})
    if base.exists():
        recent_activity.append({'event': f'Evidence directory found for {target}'})
    if urls:
        recent_activity.append({'event': f'Loaded {len(urls)} recon URLs'})
    if finding_files:
        recent_activity.append({'event': f'Loaded {len(finding_files)} finding artifacts'})

    return {
        'target': target,
        'scope': 'scope.yaml',
        'stats': {
            'targets': 1 if base.exists() else 0,
            'live_targets': 1 if urls else 0,
            'endpoints': len(urls),
            'findings': len(finding_files),
            'risk_score': risk_score,
            'agents_online': agents_online,
            'evidence_items': evidence_items,
        },
        'attack_surface': attack_surface,
        'findings_by_severity': severity_counts,
        'top_findings': top_findings,
        'recent_findings': recent_findings,
        'live_requests': live_requests,
        'recent_activity': recent_activity,
        'tooling_status': tooling_status,
    }

def _v(target, scope):
    try: validate_scope(target, scope)
    except Exception as e: raise HTTPException(status_code=400, detail=str(e))
@app.post('/api/run/recon-pipeline')
def run_recon(req: TargetRequest): _v(req.target, req.scope); return run_recon_pipeline(req.target)
@app.post('/api/run/js-url')
def run_js(req: JSUrlRequest): _v(req.target, req.scope); return analyze_js_url(req.target, req.url, ai_summary=req.ai_summary)
@app.post('/api/run/nuclei-safe')
def run_ns(req: NucleiRequest): _v(req.target, req.scope); return run_nuclei_safe(req.target, req.urls_file)
@app.post('/api/run/graphql-analyze')
def run_gql(req: GraphQLRequest): _v(req.target, req.scope); return graphql_check(req.endpoint, req.target)
@app.post('/api/run/oauth-check')
def run_o(req: OAuthRequest): _v(req.target, req.scope); return oauth_check(req.target, req.url)
@app.post('/api/run/idor-plan')
def run_id(req: IDORPlanRequest): _v(req.target, req.scope); return generate_idor_plan(req.target, req.replay_file)
@app.post('/api/run/replay-diff')
def run_replay_diff(req: ReplayDiffRequest): _v(req.target, req.scope); return replay_diff(req.target, req.request_file, req.session_a, req.session_b)
@app.post('/api/run/rank-findings')
def run_rank(req: RankRequest): _v(req.target, req.scope); return rank_findings(req.target)
@app.post('/api/report-auto')
def report_auto(req: ReportRequest): return {'report': create_report_from_evidence(req.finding, req.target)}
@app.post('/api/scope/from-chat')
def scope_from_chat(req: ScopeFromChatRequest): return create_scope_from_text(req.program, req.message, save=True, use_active=req.use_active)
@app.post('/api/scope/use')
def scope_use(req: ScopeUseRequest):
    path = use_scope(req.program)
    return {'active_scope': path, 'program': req.program}
@app.get('/api/scope/list')
def scope_list():
    return {'scopes': list_scopes(), 'active_scope': 'scope.yaml'}

@app.post('/api/chat')
def chat(req: ChatRequest):
    _v(req.target, req.scope)
    sid, mem = load_session(req.session_id)
    mem['current_target'] = req.target
    mem['current_scope'] = req.scope

    parsed = model_parse(req.message, {'target': req.target, 'scope': req.scope})
    intent = parsed.get('intent', 'none')
    params = parsed.get('params', {}) or {}
    params.setdefault('target', req.target)

    tool_call = {'tool': intent, 'params': params, 'required_parameters': required_for(intent)}
    safety = safety_for(tool_call)

    missing = missing_params(intent, params) if intent != 'none' else []
    if missing:
        mem['messages'].append({'role': 'user', 'content': req.message})
        save_session(sid, mem)
        return {
            'assistant_message': f"I need these fields before running {intent}: {', '.join(missing)}",
            'intent': intent,
            'tool_call': tool_call,
            'safety_level': safety,
            'confirmation_required': False,
            'result': None,
            'next_suggestions': [f"Provide: {m}" for m in missing],
            'session_id': sid,
        }

    confirm = safety == 'approval'
    result = None
    if intent and intent != 'none' and safety == 'safe':
        result = dispatch(intent, params)
    elif confirm:
        req = create_approval(
            project='legion-dashboard',
            target=req.target,
            agent='chat',
            action=intent,
            command_preview=f"{intent} with {params}",
            risk_level=safety,
            reason='Chat requested action requiring confirmation.',
        )
        mem['pending_confirmation'] = {'tool': intent, 'params': params, 'preview': f"{intent} with {params}", 'approval_id': req['id']}

    mem['messages'].append({'role': 'user', 'content': req.message})
    mem['last_results'] = result or mem.get('last_results', {})
    save_session(sid, mem)

    return {
        'assistant_message': parsed.get('explanation', 'Ready.'),
        'intent': intent,
        'tool_call': tool_call,
        'safety_level': safety,
        'confirmation_required': confirm,
        'approval_id': mem.get('pending_confirmation', {}).get('approval_id') if confirm else None,
        'result': result,
        'next_suggestions': parsed.get('next_suggestions', []),
        'session_id': sid,
    }

@app.post('/api/chat/confirm')
def chat_confirm(req: ChatConfirmRequest):
    sid, mem = load_session(req.session_id)
    pending = mem.get('pending_confirmation')
    if not pending:
        return {'assistant_message':'No pending confirmation.', 'result':None}
    approval_id = pending.get('approval_id')
    if approval_id:
        a = get_approval(approval_id)
        if not a:
            return {'assistant_message': 'Approval request not found.', 'result': None, 'approval_id': approval_id}
        if a.get('status') != 'approved':
            return {'assistant_message': f'Approval {approval_id} is {a.get("status", "pending")}. Action not executed.', 'result': None, 'approval_id': approval_id}
    result = dispatch(pending['tool'], pending['params'])
    mem['pending_confirmation'] = None
    mem['last_results'] = result
    save_session(sid, mem)
    return {'assistant_message':'Approved action executed.', 'result':result, 'session_id':sid}
