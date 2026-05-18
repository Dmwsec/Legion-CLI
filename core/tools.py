import shutil

TOOL_REGISTRY = [
    {'name': 'subfinder', 'category': 'recon', 'risk_level': 'safe', 'command_check': 'subfinder', 'description': 'Passive subdomain discovery'},
    {'name': 'httpx', 'category': 'recon', 'risk_level': 'safe', 'command_check': 'httpx', 'description': 'HTTP probing for live hosts'},
    {'name': 'katana', 'category': 'crawl', 'risk_level': 'safe', 'command_check': 'katana', 'description': 'Web crawling and endpoint discovery'},
    {'name': 'gau', 'category': 'recon', 'risk_level': 'safe', 'command_check': 'gau', 'description': 'Fetch URLs from historical sources'},
    {'name': 'waybackurls', 'category': 'recon', 'risk_level': 'safe', 'command_check': 'waybackurls', 'description': 'Wayback machine URL collection'},
    {'name': 'subjs', 'category': 'js', 'risk_level': 'safe', 'command_check': 'subjs', 'description': 'JavaScript URL discovery'},
    {'name': 'assetfinder', 'category': 'recon', 'risk_level': 'safe', 'command_check': 'assetfinder', 'description': 'Find related domains and assets'},
    {'name': 'amass', 'category': 'recon', 'risk_level': 'approval', 'command_check': 'amass', 'description': 'Extensive subdomain enumeration'},
    {'name': 'dnsx', 'category': 'recon', 'risk_level': 'safe', 'command_check': 'dnsx', 'description': 'DNS resolution and filtering'},
    {'name': 'naabu', 'category': 'network', 'risk_level': 'approval', 'command_check': 'naabu', 'description': 'Fast port scanning'},
    {'name': 'nmap', 'category': 'network', 'risk_level': 'approval', 'command_check': 'nmap', 'description': 'Network and service scanning'},
    {'name': 'masscan', 'category': 'network', 'risk_level': 'approval', 'command_check': 'masscan', 'description': 'High-speed port scanner'},
    {'name': 'ffuf', 'category': 'fuzzing', 'risk_level': 'approval', 'command_check': 'ffuf', 'description': 'Web content and parameter fuzzing'},
    {'name': 'wfuzz', 'category': 'fuzzing', 'risk_level': 'approval', 'command_check': 'wfuzz', 'description': 'Flexible web fuzzer'},
    {'name': 'arjun', 'category': 'fuzzing', 'risk_level': 'approval', 'command_check': 'arjun', 'description': 'Hidden parameter discovery'},
    {'name': 'dalfox', 'category': 'xss', 'risk_level': 'approval', 'command_check': 'dalfox', 'description': 'XSS scanner and verification'},
    {'name': 'nuclei', 'category': 'scanner', 'risk_level': 'approval', 'command_check': 'nuclei', 'description': 'Template-based vuln scanner'},
    {'name': 'sqlmap', 'category': 'injection', 'risk_level': 'manual', 'command_check': 'sqlmap', 'description': 'SQL injection testing'},
    {'name': 'commix', 'category': 'injection', 'risk_level': 'manual', 'command_check': 'commix', 'description': 'Command injection testing'},
    {'name': 'nikto', 'category': 'scanner', 'risk_level': 'approval', 'command_check': 'nikto', 'description': 'Web server scanner'},
    {'name': 'wpscan', 'category': 'cms', 'risk_level': 'approval', 'command_check': 'wpscan', 'description': 'WordPress scanner'},
    {'name': 'joomscan', 'category': 'cms', 'risk_level': 'approval', 'command_check': 'joomscan', 'description': 'Joomla scanner'},
    {'name': 'ghauri', 'category': 'injection', 'risk_level': 'manual', 'command_check': 'ghauri', 'description': 'SQLi automation engine'},
    {'name': 'gobuster', 'category': 'fuzzing', 'risk_level': 'approval', 'command_check': 'gobuster', 'description': 'Directory/DNS brute force'},
    {'name': 'dirsearch', 'category': 'fuzzing', 'risk_level': 'approval', 'command_check': 'dirsearch', 'description': 'Path and file brute force'},
    {'name': 'feroxbuster', 'category': 'fuzzing', 'risk_level': 'approval', 'command_check': 'feroxbuster', 'description': 'Recursive content discovery'},
    {'name': 'hakrawler', 'category': 'crawl', 'risk_level': 'safe', 'command_check': 'hakrawler', 'description': 'Quick web crawling'},
    {'name': 'gospider', 'category': 'crawl', 'risk_level': 'safe', 'command_check': 'gospider', 'description': 'Web spidering for endpoints'},
    {'name': 'xnLinkFinder', 'category': 'js', 'risk_level': 'safe', 'command_check': 'xnLinkFinder', 'description': 'Endpoint extraction from JS/HTML'},
    {'name': 'linkfinder', 'category': 'js', 'risk_level': 'safe', 'command_check': 'linkfinder', 'description': 'Regex endpoint extraction from JS'},
    {'name': 'secretfinder', 'category': 'secrets', 'risk_level': 'safe', 'command_check': 'secretfinder', 'description': 'Secrets in JS files'},
    {'name': 'trufflehog', 'category': 'secrets', 'risk_level': 'safe', 'command_check': 'trufflehog', 'description': 'Secret scanning in repos/files'},
    {'name': 'gitleaks', 'category': 'secrets', 'risk_level': 'safe', 'command_check': 'gitleaks', 'description': 'Secrets detection engine'},
    {'name': 'jwt-tool', 'category': 'auth', 'risk_level': 'approval', 'command_check': 'jwt-tool', 'description': 'JWT analysis toolkit'},
    {'name': 'jwt-cracker', 'category': 'auth', 'risk_level': 'manual', 'command_check': 'jwt-cracker', 'description': 'JWT brute-force/crack helper'},
    {'name': 'corsy', 'category': 'misconfig', 'risk_level': 'safe', 'command_check': 'corsy', 'description': 'CORS misconfiguration scanner'},
    {'name': 'smuggler', 'category': 'http', 'risk_level': 'manual', 'command_check': 'smuggler', 'description': 'HTTP request smuggling checks'},
    {'name': 'race-the-web', 'category': 'logic', 'risk_level': 'manual', 'command_check': 'race-the-web', 'description': 'Race condition testing'},
    {'name': 'kiterunner', 'category': 'api', 'risk_level': 'approval', 'command_check': 'kr', 'description': 'API endpoint discovery/fuzzing'},
    {'name': 'graphql-voyager', 'category': 'graphql', 'risk_level': 'safe', 'command_check': 'graphql-voyager', 'description': 'GraphQL schema visualization'},
    {'name': 'inql', 'category': 'graphql', 'risk_level': 'approval', 'command_check': 'inql', 'description': 'GraphQL testing toolkit'},
    {'name': 'burp-suite', 'category': 'proxy', 'risk_level': 'manual', 'command_check': 'burpsuite', 'description': 'Manual web proxy and testing'},
    {'name': 'caido', 'category': 'proxy', 'risk_level': 'manual', 'command_check': 'caido', 'description': 'Web security testing proxy'},
    {'name': 'zap', 'category': 'proxy', 'risk_level': 'approval', 'command_check': 'zap.sh', 'description': 'OWASP ZAP scanner/proxy'},
    {'name': 'playwright', 'category': 'browser', 'risk_level': 'safe', 'command_check': 'playwright', 'description': 'Browser automation capture'},
    {'name': 'mitmproxy', 'category': 'proxy', 'risk_level': 'manual', 'command_check': 'mitmproxy', 'description': 'Traffic interception proxy'},
    {'name': 'apktool', 'category': 'mobile', 'risk_level': 'manual', 'command_check': 'apktool', 'description': 'Android APK reversing'},
    {'name': 'jadx', 'category': 'mobile', 'risk_level': 'manual', 'command_check': 'jadx', 'description': 'Android decompiler'},
    {'name': 'frida', 'category': 'mobile', 'risk_level': 'manual', 'command_check': 'frida', 'description': 'Dynamic instrumentation toolkit'},
    {'name': 'mobfs', 'category': 'mobile', 'risk_level': 'manual', 'command_check': 'MobSF', 'description': 'Mobile app static/dynamic analyzer'},
    {'name': 'metasploit', 'category': 'validation', 'risk_level': 'manual', 'command_check': 'msfconsole', 'description': 'Controlled Metasploit validation; exploit modules blocked by default'},
]


def get_tools_with_status() -> list[dict]:
    tools = []
    for item in TOOL_REGISTRY:
        installed = shutil.which(item['command_check']) is not None
        tools.append({**item, 'installed': installed})
    return tools


def list_tools():
    tools = get_tools_with_status()
    print('\n[Legion Tool Registry - 50 Tools]\n')
    for level in ('safe', 'approval', 'manual'):
        group = [t for t in tools if t['risk_level'] == level]
        print(f'{level.upper()} ({len(group)}):')
        for t in sorted(group, key=lambda x: x['name']):
            status = 'INSTALLED' if t['installed'] else 'MISSING'
            marker = '✅' if t['installed'] else '❌'
            print(f"  {marker} {t['name']} [{t['category']}] - {status} :: {t['description']}")
        print()

    installed = sum(1 for t in tools if t['installed'])
    print(f'[+] Installed: {installed}/{len(tools)}')
