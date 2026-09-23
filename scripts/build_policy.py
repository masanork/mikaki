"""Compile the validated deployment policy for the local slice (Python 3.11+)."""
import json
import hashlib
import sys
import tomllib
from pathlib import Path
from check_design import ROOT, revision, validate

source = Path(sys.argv[1]) if len(sys.argv) > 1 else ROOT / 'config/runtime-policy.example.toml'
policy = tomllib.loads(source.read_text())
output = ROOT / 'local/generated/policy.json'
output.parent.mkdir(parents=True, exist_ok=True)
normalized = validate(policy)
policy_revision = revision(policy)
output.write_text(json.dumps({**normalized, 'policy_revision': policy_revision}, indent=2) + '\n')
worker_policy = {
    'schema_version': 5,
    'policy_revision': policy_revision,
    'assertion_ttl_seconds': normalized['oidc.client_authentication.assertion_ttl'],
    'clock_skew_seconds': normalized['oidc.validation.clock_skew'],
    'authorization_code_ttl_seconds': normalized['oidc.authorization_code_ttl'],
    'request_target_bytes': normalized['limits.request_target_bytes'],
    'parameter_count': normalized['limits.parameter_count'],
    'state_bytes': normalized['limits.state_bytes'],
    'nonce_bytes': normalized['limits.nonce_bytes'],
    'access_token_ttl_seconds': normalized['oidc.access_token.ttl'],
    'id_token_ttl_seconds': normalized['oidc.id_token_ttl'],
    'response_bytes': normalized['limits.response_bytes'],
    'jwt_bytes': normalized['limits.jwt_bytes'],
    'form_body_bytes': normalized['limits.form_body_bytes'],
    'token_rate_window_seconds': normalized['rate_limit.window'],
    'token_attempts_per_client': normalized['rate_limit.token_per_authenticated_client'],
    'sso_absolute_ttl_seconds': normalized['session.sso_absolute_ttl'],
}
worker_policy['policy_revision'] = policy_revision
worker_policy['projection_revision'] = hashlib.sha256(
    json.dumps(worker_policy, sort_keys=True, separators=(',', ':')).encode('ascii')
).hexdigest()
(ROOT / 'local/generated/worker-policy.json').write_text(
    json.dumps(worker_policy, sort_keys=True, separators=(',', ':')) + '\n'
)
print('Validated policy compiled: ' + policy_revision)
