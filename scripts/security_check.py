"""Safety guard for auto-fix workflow.

Ensures auto-fix run does not touch forbidden files/paths.
"""

import subprocess

FORBIDDEN_PREFIXES = (
    'data/',
    'evidence/',
    'logs/',
    'approvals/',
)
FORBIDDEN_FILES = {'.env'}
FORBIDDEN_HINTS = ('exploit', 'scope guard', 'approval gate')


def changed_files() -> list[str]:
    proc = subprocess.run(['git', 'status', '--porcelain'], capture_output=True, text=True, check=True)
    files: list[str] = []
    for line in proc.stdout.splitlines():
        if not line:
            continue
        path = line[3:]
        if ' -> ' in path:
            path = path.split(' -> ', 1)[1]
        files.append(path)
    return files


def main() -> int:
    for path in changed_files():
        low = path.lower()
        if path in FORBIDDEN_FILES or any(low.startswith(p) for p in FORBIDDEN_PREFIXES):
            print(f'[!] Forbidden auto-fix path touched: {path}')
            return 1
        if any(h in low for h in FORBIDDEN_HINTS):
            print(f'[!] Risky file name touched by auto-fix: {path}')
            return 1
    print('[+] Auto-fix safety check passed.')
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
