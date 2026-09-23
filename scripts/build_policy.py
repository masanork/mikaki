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
    'schema_version': normalized['schema_version'],
    'policy_revision': policy_revision,
    'assertion_ttl_seconds': normalized['oidc.client_authentication.assertion_ttl'],
    'clock_skew_seconds': normalized['oidc.validation.clock_skew'],
    'jwt_bytes': normalized['limits.jwt_bytes'],
    'form_body_bytes': normalized['limits.form_body_bytes'],
}
worker_policy['policy_revision'] = policy_revision
worker_policy['projection_revision'] = hashlib.sha256(
    json.dumps(worker_policy, sort_keys=True, separators=(',', ':')).encode('ascii')
).hexdigest()
(ROOT / 'local/generated/worker-policy.json').write_text(
    json.dumps(worker_policy, sort_keys=True, separators=(',', ':')) + '\n'
)
print('Validated policy compiled: ' + policy_revision)
