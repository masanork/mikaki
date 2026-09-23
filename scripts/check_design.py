#!/usr/bin/env python3
"""Validate design artifacts with Python 3.11+; this is not the product policy loader."""
import copy
import hashlib
import json
import os
import re
import tomllib
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
DURATION_GROUPS = {
    'registration': 'invitation_ttl bootstrap_invitation_ttl',
    'authentication': 'ceremony_ttl',
    'session': 'sso_absolute_ttl app_idle_timeout',
    'session.validation': 'lease_ttl',
    'session.management': 'operation_authorization_ttl',
    'oidc': 'authorization_code_ttl id_token_ttl',
    'oidc.login': 'transaction_ttl',
    'oidc.client_authentication': 'assertion_ttl',
    'oidc.access_token': 'ttl',
    'oidc.validation': 'clock_skew',
    'oidc.backchannel': 'request_timeout',
    'oidc_logout': 'token_ttl',
    'signing': 'rotation_interval prepublish_duration jwks_cache_max_age verification_key_min_retention deployment_margin',
    'jwks_fetch': 'timeout unknown_kid_cooldown negative_cache_ttl',
    'rate_limit': 'window',
    'logout_delivery': 'base_delay max_delay retry_deadline lease_ttl scheduler_interval oldest_pending_alert_age',
    'retention': 'gc_interval gc_grace audit_ttl delivery_result_ttl rate_key_ttl',
    'vault': 'unlock_idle_timeout unlock_absolute_ttl',
}
COUNT_GROUPS = {
    'authentication': 'ceremony_max_failures',
    'jwks_fetch': 'max_inflight_per_issuer negative_cache_entries_per_issuer',
    'limits': 'request_target_bytes header_bytes form_body_bytes json_body_bytes webauthn_body_bytes webauthn_depth jwt_bytes jwks_bytes jwks_keys json_depth parameter_count state_bytes nonce_bytes jti_bytes kid_bytes client_id_bytes redirect_uri_bytes scope_bytes pending_login_per_browser active_sso_per_account active_client_sessions_per_sso_client registered_clients credentials_per_account response_bytes',
    'rate_limit': 'discovery_per_ip authorize_per_browser authorize_per_ip ceremony_start_per_browser ceremony_finish_per_browser token_per_ip token_per_authenticated_client userinfo_per_ip session_check_per_authenticated_client management_per_account logout_receive_per_authenticated_issuer',
    'logout_delivery': 'max_attempts fanout_batch_size claim_batch_size max_inflight_per_client max_response_bytes backlog_alert_count',
    'retention': 'gc_batch_size',
}
DURATIONS = {g+'.'+k for g, keys in DURATION_GROUPS.items() for k in keys.split()}
COUNTS = {g+'.'+k for g, keys in COUNT_GROUPS.items() for k in keys.split()}


def flatten(data, prefix=''):
    result = {}
    for k, value in data.items():
        key = prefix+k
        if isinstance(value, dict):
            result.update(flatten(value, key+'.'))
        else:
            result[key] = value
    return result


def require(condition, message):
    if not condition:
        raise ValueError(message)


def validate(data):
    values = flatten(data)
    expected = DURATIONS | COUNTS | {'schema_version'}
    tables = {'.'.join(k.split('.')[:i]) for k in expected for i in range(1, len(k.split('.')))}
    def check_tables(node, prefix=''):
        for k, value in node.items():
            path = prefix+k
            if isinstance(value, dict):
                require(path in tables, 'unknown table: '+path)
                check_tables(value, path+'.')
    check_tables(data)
    require(set(values) == expected, 'unknown/missing keys: '+str(set(values) ^ expected))
    require(type(values['schema_version']) is int and values['schema_version'] == 1, 'schema_version')
    out = {'schema_version': 1}
    for key in sorted(DURATIONS | COUNTS):
        value = values[key]
        if key in DURATIONS:
            match = re.fullmatch(r'([1-9][0-9]*)([smhd])', value) if isinstance(value, str) else None
            require(match is not None, key+': positive duration required')
            value = int(match[1]) * {'s': 1, 'm': 60, 'h': 3600, 'd': 86400}[match[2]]
        require(type(value) is int and 0 < value <= 2**31-1, key+': positive bounded integer required')
        out[key] = value
    def le(a, b):
        require(out[a] <= out[b], a+' must be <= '+b)
    for a, b in [
        ('session.app_idle_timeout', 'session.sso_absolute_ttl'),
        ('session.validation.lease_ttl', 'session.app_idle_timeout'),
        ('session.management.operation_authorization_ttl', 'session.sso_absolute_ttl'),
        ('oidc.authorization_code_ttl', 'session.sso_absolute_ttl'),
        ('oidc.authorization_code_ttl', 'oidc.login.transaction_ttl'),
        ('oidc.access_token.ttl', 'session.sso_absolute_ttl'),
        ('oidc.id_token_ttl', 'session.sso_absolute_ttl'),
        ('vault.unlock_idle_timeout', 'vault.unlock_absolute_ttl'),
        ('logout_delivery.base_delay', 'logout_delivery.max_delay'),
        ('logout_delivery.max_delay', 'logout_delivery.retry_deadline'),
        ('logout_delivery.lease_ttl', 'logout_delivery.retry_deadline'),
        ('logout_delivery.oldest_pending_alert_age', 'logout_delivery.retry_deadline'),
        ('jwks_fetch.negative_cache_ttl', 'signing.prepublish_duration'),
        ('jwks_fetch.unknown_kid_cooldown', 'signing.prepublish_duration'),
        ('limits.jwt_bytes', 'limits.form_body_bytes'),
        ('limits.jwt_bytes', 'limits.json_body_bytes'),
        ('limits.jwks_bytes', 'limits.response_bytes'),
    ]:
        le(a, b)
    require(out['oidc.backchannel.request_timeout'] < out['logout_delivery.lease_ttl'], 'delivery lease must exceed HTTP timeout')
    require(out['jwks_fetch.timeout'] < out['oidc.backchannel.request_timeout'], 'JWKS timeout must leave processing time')
    require(out['signing.prepublish_duration'] >= out['signing.jwks_cache_max_age'] + out['oidc.validation.clock_skew'] + out['signing.deployment_margin'], 'prepublish too short')
    require(out['signing.rotation_interval'] > out['signing.prepublish_duration'], 'rotation <= prepublish')
    require(out['limits.jwt_bytes']+4096 <= out['limits.header_bytes'], 'header budget too small')
    require(out['limits.jwt_bytes']+4096 <= out['limits.form_body_bytes'], 'form budget too small')
    require(out['rate_limit.window'] in (10, 60), 'Cloudflare rate window must be 10s or 60s')
    # profile-specific hard ceilings are deliberate review boundaries, not silent clamps.
    require(out['limits.json_depth'] <= 64, 'json_depth exceeds tested profile')
    require(out['limits.webauthn_depth'] <= 64, 'webauthn_depth exceeds tested profile')
    require(out['limits.jwks_keys'] <= 128, 'jwks_keys exceeds tested profile')
    require(all(out[k] <= 1048576 for k in COUNTS if k.endswith('_bytes')), 'byte bound exceeds initial profile')
    return out


def revision(data):
    normalized = json.dumps(validate(data), sort_keys=True, separators=(',', ':'), ensure_ascii=True)
    return hashlib.sha256(normalized.encode('ascii')).hexdigest()


def set_key(data, path, value):
    keys = path.split('.')
    for key in keys[:-1]:
        data = data[key]
    data[keys[-1]] = value


def main():
    policy = tomllib.loads((ROOT/'config/runtime-policy.example.toml').read_text())
    normalized = validate(policy)
    for p in (ROOT/'config').glob('*.toml'):
        part = tomllib.loads(p.read_text())
        for key, value in flatten(part).items():
            require(flatten(policy).get(key) == value, f'{p.name}: conflicting historical example {key}')
    invalid = [
        ('schema_version', 2), ('schema_version', True),
        ('authentication.ceremony_max_failures', 0), ('limits.jwt_bytes', True),
        ('limits.jwt_bytes', -1), ('limits.json_depth', 65), ('limits.header_bytes', 2048),
        ('session.sso_absolute_ttl', '0s'), ('session.sso_absolute_ttl', '1h'),
        ('oidc.access_token.ttl', '2m30s'), ('oidc.access_token.ttl', '999999999999999999d'),
        ('oidc.validation.clock_skew', 30), ('logout_delivery.lease_ttl', '1s'),
        ('logout_delivery.max_delay', '2d'), ('signing.prepublish_duration', '1s'),
        ('jwks_fetch.timeout', '1h'), ('rate_limit.window', '30s'),
    ]
    for path, value in invalid:
        candidate = copy.deepcopy(policy); set_key(candidate, path, value)
        try:
            validate(candidate)
        except ValueError:
            pass
        else:
            raise AssertionError('accepted invalid setting: '+path)
    for change in ('unknown', 'missing', 'empty_unknown_table'):
        candidate = copy.deepcopy(policy)
        if change == 'unknown': candidate['unexpected'] = 1
        elif change == 'missing': del candidate['oidc']['access_token']['ttl']
        else: candidate['oidc']['unknown'] = {}
        try: validate(candidate)
        except ValueError: pass
        else: raise AssertionError('accepted '+change+' key')
    equivalent = copy.deepcopy(policy); equivalent['oidc']['access_token']['ttl'] = '300s'
    require(revision(equivalent) == revision(policy), 'duration normalization changed revision')
    for directory, subdirs, files in os.walk(ROOT):
        subdirs[:] = [name for name in subdirs if name not in {
            '.git', 'node_modules', 'target', 'pkg', 'pkg-web', '.wrangler', '__pycache__',
        }]
        for name in files:
            if not name.endswith('.md'):
                continue
            p = Path(directory)/name
            for target in re.findall(r'\]\(([^)]+)\)', p.read_text()):
                if '://' not in target and not target.startswith('#'):
                    require((p.parent/target.split('#')[0]).exists(), f'broken link: {p}: {target}')
    print(f'OK: {len(normalized)} configuration fields; 20 invalid configurations rejected; normalized revision stable; local links valid')
    print('policy_revision='+revision(policy))


if __name__ == '__main__':
    main()
