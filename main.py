import argparse
from pathlib import Path

from core.tools import list_tools
from core.scope import validate_scope
from core.report import create_report, create_report_from_evidence
from ai.reasoner import plan_next_step
from modules.recon import run_recon
from modules.recon_pipeline import run_recon_pipeline
from modules.api_analyzer import classify_and_store_endpoints, run_auth_diff
from modules.traffic_import import import_burp_xml, import_caido_json
from modules.evidence_manager import init_evidence_tree
from modules.idor_bola import analyze_idor_from_replay
from modules.idor import generate_idor_plan, run_idor_test
from modules.js_routes import extract_js_routes
from modules.nuclei_safe import run_nuclei_safe
from modules.graphql import graphql_check
from modules.js_analyzer import analyze_js_url, analyze_js_file
from modules.oauth import oauth_check
from core.job_queue import JobQueue
from modules.scope_builder import create_scope_from_file, use_scope, list_scopes, show_scope
from modules.traffic_summary import traffic_summary
from web.agent import terminal_chat
from modules.security_workflows import race_condition_workflow,payment_logic_workflow,ssrf_chain_workflow,request_smuggling_workflow,mobile_reversing_workflow,cloud_misconfig_workflow,business_logic_workflow
from modules.replay_engine import replay_diff
from modules.finding_ranker import rank_findings


def _read_text(path: str) -> str:
    p = Path(path)
    if not p.exists():
        raise FileNotFoundError(f'File not found: {path}')
    return p.read_text()


def _read_lines(path: str) -> list[str]:
    return [line.strip() for line in _read_text(path).splitlines() if line.strip()]


def main():
    parser = argparse.ArgumentParser(description='Legion CLI')
    sub = parser.add_subparsers(dest='command')
    sub.add_parser('tools')
    dashboard = sub.add_parser('dashboard'); dashboard.add_argument('--host', default='127.0.0.1'); dashboard.add_argument('--port', type=int, default=9000)
    recon = sub.add_parser('recon'); recon.add_argument('target'); recon.add_argument('--scope', default='scope.yaml')
    recon_pipeline = sub.add_parser('recon-pipeline'); recon_pipeline.add_argument('target'); recon_pipeline.add_argument('--scope', default='scope.yaml')
    classify = sub.add_parser('classify-endpoints'); classify.add_argument('target'); classify.add_argument('--input', required=True); classify.add_argument('--scope', default='scope.yaml')
    authdiff = sub.add_parser('auth-diff'); authdiff.add_argument('target'); authdiff.add_argument('--endpoint', required=True); authdiff.add_argument('--unauth-file', required=True); authdiff.add_argument('--auth-file', required=True); authdiff.add_argument('--scope', default='scope.yaml')
    evidence = sub.add_parser('evidence-init'); evidence.add_argument('target')
    idor = sub.add_parser('idor-bola'); idor.add_argument('target'); idor.add_argument('--replay-file', required=True)
    idor_plan = sub.add_parser('idor-plan'); idor_plan.add_argument('target'); idor_plan.add_argument('--replay-file', required=True); idor_plan.add_argument('--scope', default='scope.yaml')
    idor_test = sub.add_parser('idor-test'); idor_test.add_argument('target'); idor_test.add_argument('--plan', required=True); idor_test.add_argument('--user-a-token', required=True); idor_test.add_argument('--user-b-token', required=True); idor_test.add_argument('--scope', default='scope.yaml')
    idor_engine = sub.add_parser('idor-engine'); idor_engine.add_argument('target'); idor_engine.add_argument('--replay-file', required=True); idor_engine.add_argument('--scope', default='scope.yaml')
    js_routes = sub.add_parser('js-routes'); js_routes.add_argument('target'); js_routes.add_argument('--js-file', required=True); js_routes.add_argument('--scope', default='scope.yaml')
    nuclei_safe = sub.add_parser('nuclei-safe'); nuclei_safe.add_argument('target'); nuclei_safe.add_argument('--urls-file', required=True); nuclei_safe.add_argument('--scope', default='scope.yaml')
    gql = sub.add_parser('graphql-analyze'); gql.add_argument('target'); gql.add_argument('--endpoint', required=True); gql.add_argument('--scope', default='scope.yaml')
    oauth = sub.add_parser('oauth-check'); oauth.add_argument('target'); oauth.add_argument('--url', required=True); oauth.add_argument('--scope', default='scope.yaml')
    report_auto = sub.add_parser('report-auto'); report_auto.add_argument('finding'); report_auto.add_argument('--target', required=True)
    imp = sub.add_parser('import-traffic'); imp.add_argument('source', choices=['burp', 'caido']); imp.add_argument('file'); imp.add_argument('--target')
    js_url = sub.add_parser('js-url'); js_url.add_argument('target'); js_url.add_argument('--url', required=True); js_url.add_argument('--ai-summary', action='store_true'); js_url.add_argument('--scope', default='scope.yaml')
    js_file = sub.add_parser('js-file'); js_file.add_argument('target'); js_file.add_argument('--file', required=True); js_file.add_argument('--ai-summary', action='store_true'); js_file.add_argument('--scope', default='scope.yaml')
    js = sub.add_parser('js'); js.add_argument('target'); js.add_argument('--scope', default='scope.yaml')
    api = sub.add_parser('api'); api.add_argument('target'); api.add_argument('--scope', default='scope.yaml')
    ai_plan = sub.add_parser('ai-plan'); ai_plan.add_argument('target')
    report = sub.add_parser('report'); report.add_argument('finding'); report.add_argument('--target', required=True); report.add_argument('--ai-draft', action='store_true'); report.add_argument('--evidence-file')
    sft = sub.add_parser('scope-from-text'); sft.add_argument('program'); sft.add_argument('--file', required=True)
    su = sub.add_parser('scope-use'); su.add_argument('program')
    sl = sub.add_parser('scope-list')
    ss = sub.add_parser('scope-show'); ss.add_argument('program')
    sw = sub.add_parser('security-workflow'); sw.add_argument('target'); sw.add_argument('--type', required=True, choices=['race','payment','ssrf','smuggling','mobile','cloud','business']); sw.add_argument('--scope', default='scope.yaml')
    rd = sub.add_parser('replay-diff'); rd.add_argument('target'); rd.add_argument('--request-file', required=True); rd.add_argument('--session-a', required=True); rd.add_argument('--session-b', required=True); rd.add_argument('--scope', default='scope.yaml')
    rf = sub.add_parser('rank-findings'); rf.add_argument('target'); rf.add_argument('--scope', default='scope.yaml')
    ts = sub.add_parser('traffic-summary'); ts.add_argument('target')
    sub.add_parser('agent-chat')
    args = parser.parse_args()

    try:
        if args.command == 'tools': list_tools()
        elif args.command == 'dashboard':
            import uvicorn
            uvicorn.run('web.app:app', host=args.host, port=args.port, reload=False)
        elif args.command == 'recon': validate_scope(args.target, args.scope); q=JobQueue(max_workers=1); f=q.submit(run_recon, args.target); f.result(); q.shutdown()
        elif args.command == 'recon-pipeline': validate_scope(args.target, args.scope); print(run_recon_pipeline(args.target))
        elif args.command == 'classify-endpoints': validate_scope(args.target, args.scope); print(f"[+] Classified {len(classify_and_store_endpoints(args.target, _read_lines(args.input)))} endpoints")
        elif args.command == 'auth-diff': validate_scope(args.target, args.scope); print(run_auth_diff(args.target, args.endpoint, _read_text(args.unauth_file), _read_text(args.auth_file)))
        elif args.command == 'evidence-init': print(f'[+] Evidence tree ready: {init_evidence_tree(args.target)}')
        elif args.command == 'idor-bola': print(analyze_idor_from_replay(args.target, args.replay_file))
        elif args.command == 'idor-plan': validate_scope(args.target, args.scope); print(generate_idor_plan(args.target, args.replay_file))
        elif args.command == 'idor-test': validate_scope(args.target, args.scope); print(run_idor_test(args.target, args.plan, args.user_a_token, args.user_b_token))
        elif args.command == 'idor-engine': validate_scope(args.target, args.scope); print(generate_idor_plan(args.target, args.replay_file))
        elif args.command == 'js-routes': validate_scope(args.target, args.scope); print(extract_js_routes(args.target, args.js_file))
        elif args.command == 'nuclei-safe': validate_scope(args.target, args.scope); print(run_nuclei_safe(args.target, args.urls_file))
        elif args.command == 'graphql-analyze': validate_scope(args.target, args.scope); print(graphql_check(args.endpoint, args.target))
        elif args.command == 'oauth-check': validate_scope(args.target, args.scope); print(oauth_check(args.target, args.url))
        elif args.command == 'report-auto': print(create_report_from_evidence(args.finding, args.target))
        elif args.command == 'import-traffic': print(import_burp_xml(args.file, target=args.target) if args.source == 'burp' else import_caido_json(args.file, target=args.target))
        elif args.command == 'js-url': validate_scope(args.target, args.scope); print(analyze_js_url(args.target, args.url, ai_summary=args.ai_summary))
        elif args.command == 'js-file': validate_scope(args.target, args.scope); print(analyze_js_file(args.target, args.file, ai_summary=args.ai_summary))
        elif args.command == 'js': validate_scope(args.target, args.scope); print(f'[+] JS intelligence workflow prepared for {args.target}')
        elif args.command == 'api': validate_scope(args.target, args.scope); print(f'[+] API analysis workflow prepared for {args.target}')
        elif args.command == 'ai-plan': print(plan_next_step(args.target))
        elif args.command == 'report': create_report(args.finding, args.target, ai_draft=args.ai_draft, evidence=_read_text(args.evidence_file) if args.evidence_file else '')
        elif args.command == 'scope-from-text': print(create_scope_from_file(args.program, args.file))
        elif args.command == 'scope-use': print({'active_scope': use_scope(args.program), 'program': args.program})
        elif args.command == 'scope-list': print({'scopes': list_scopes()})
        elif args.command == 'scope-show': print(show_scope(args.program))
        elif args.command == 'traffic-summary': print(traffic_summary(args.target))
        elif args.command == 'agent-chat': terminal_chat()
        elif args.command == 'replay-diff': validate_scope(args.target, args.scope); print(replay_diff(args.target, args.request_file, args.session_a, args.session_b))
        elif args.command == 'rank-findings': validate_scope(args.target, args.scope); print(rank_findings(args.target))
        elif args.command == 'security-workflow':
            validate_scope(args.target, args.scope)
            mapping = {
                'race': race_condition_workflow,
                'payment': payment_logic_workflow,
                'ssrf': ssrf_chain_workflow,
                'smuggling': request_smuggling_workflow,
                'mobile': mobile_reversing_workflow,
                'cloud': cloud_misconfig_workflow,
                'business': business_logic_workflow,
            }
            print(mapping[args.type](args.target))
        else: parser.print_help()
    except (FileNotFoundError, ValueError, Exception) as exc:
        print(f'[!] Error: {exc}')
        raise SystemExit(1)


if __name__ == '__main__':
    main()
