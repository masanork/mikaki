"""Compile the validated deployment policy for the local slice (Python 3.11+)."""
import json
import sys
import tomllib
from pathlib import Path
from check_design import ROOT, revision, validate

source = Path(sys.argv[1]) if len(sys.argv) > 1 else ROOT / 'config/runtime-policy.example.toml'
policy = tomllib.loads(source.read_text())
output = ROOT / 'local/generated/policy.json'
output.parent.mkdir(parents=True, exist_ok=True)
output.write_text(json.dumps({**validate(policy), 'policy_revision': revision(policy)}, indent=2) + '\n')
print('Validated policy compiled: ' + revision(policy))
