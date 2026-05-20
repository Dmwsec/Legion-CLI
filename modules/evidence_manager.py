from pathlib import Path

from core.safe_paths import safe_filename, safe_join, safe_target_name


EVIDENCE_ROOT = Path('evidence')
EVIDENCE_SUBDIRS = [
    'requests',
    'responses',
    'screenshots',
    'ai-analysis',
    'replay',
]


def normalize_target(target: str) -> str:
    return safe_target_name(target)


def init_evidence_tree(target: str) -> Path:
    normalized = normalize_target(target)
    root = safe_join(EVIDENCE_ROOT, normalized)
    root.mkdir(parents=True, exist_ok=True)
    for sub in EVIDENCE_SUBDIRS:
        safe_join(root, sub).mkdir(parents=True, exist_ok=True)
    return root


def evidence_path(target: str, category: str, filename: str) -> Path:
    if category not in EVIDENCE_SUBDIRS:
        raise ValueError(f'Unknown evidence category: {category}')
    root = init_evidence_tree(target)
    category_dir = safe_join(root, category)
    return safe_join(category_dir, safe_filename(filename))
