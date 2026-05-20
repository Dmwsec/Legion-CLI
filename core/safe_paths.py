import re
from pathlib import Path
from urllib.parse import urlparse


_SAFE_NAME_RE = re.compile(r'[^A-Za-z0-9._-]+')
_RESERVED_NAMES = {'', '.', '..'}


def _clean_name(value: str, fallback: str) -> str:
    text = (value or '').strip().replace('\x00', '')
    if not text:
        return fallback
    text = text.replace('\\', '/').split('/')[-1]
    text = _SAFE_NAME_RE.sub('_', text).strip('._-')
    if text in _RESERVED_NAMES:
        return fallback
    return text[:180] or fallback


def safe_target_name(target: str) -> str:
    parsed = urlparse((target or '').strip())
    candidate = parsed.netloc or parsed.path or target
    candidate = candidate.split('@')[-1].split(':')[0] if candidate else ''
    return _clean_name(candidate, 'unknown-target')


def safe_filename(name: str) -> str:
    return _clean_name(name, 'artifact.txt')


def safe_join(base: Path, *parts: str) -> Path:
    base_resolved = base.resolve()
    clean_parts = [safe_filename(part) for part in parts]
    final = base_resolved.joinpath(*clean_parts).resolve()
    if final != base_resolved and base_resolved not in final.parents:
        raise ValueError('Path traversal blocked')
    return final
