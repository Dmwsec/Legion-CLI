import pytest
import yaml

from core.scope import validate_scope


def _scope(tmp_path, allowed, out=None):
    p = tmp_path / 'scope.yaml'
    p.write_text(yaml.safe_dump({'allowed_domains': allowed, 'out_of_scope': out or []}))
    return str(p)


def test_wildcard_allowed(tmp_path):
    scope = _scope(tmp_path, ['*.example.com'])
    validate_scope('api.example.com', scope)


def test_exact_allowed(tmp_path):
    scope = _scope(tmp_path, ['example.com'])
    validate_scope('example.com', scope)


def test_out_of_scope_overrides_allowed(tmp_path):
    scope = _scope(tmp_path, ['example.com'], ['api.example.com'])
    with pytest.raises(ValueError, match='out-of-scope'):
        validate_scope('api.example.com', scope)


def test_invalid_target_blocked(tmp_path):
    scope = _scope(tmp_path, ['example.com'])
    with pytest.raises(ValueError, match='Invalid target'):
        validate_scope('', scope)
