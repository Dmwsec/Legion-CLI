"""Apply safe repository hygiene fixes for CI failures.

Allowed fixes:
- remove unused imports/format via external ruff steps
- add missing __init__.py for importable package dirs
- keep changes away from exploit/security control logic
"""

from pathlib import Path

PACKAGE_DIRS = ['agents', 'ai', 'browser', 'core', 'modules', 'storage', 'traffic', 'web']


def ensure_init_files() -> list[Path]:
    created: list[Path] = []
    for d in PACKAGE_DIRS:
        p = Path(d)
        if p.is_dir():
            init = p / '__init__.py'
            if not init.exists():
                init.write_text('', encoding='utf-8')
                created.append(init)
    return created


def main() -> int:
    created = ensure_init_files()
    if created:
        for p in created:
            print(f'[+] Created missing package marker: {p}')
    else:
        print('[+] No missing __init__.py files found.')
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
