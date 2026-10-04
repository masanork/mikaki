-- Fresh Owner Vault and Identity D1 baseline. Apply only to an empty database.
-- Historical data and migration ledgers are intentionally not upgraded by this file.

CREATE TABLE account_role (
  account_id TEXT NOT NULL REFERENCES account_security(account_id),
  role TEXT NOT NULL CHECK(role = 'admin'),
  active INTEGER NOT NULL CHECK(active IN (0, 1)),
  PRIMARY KEY(account_id,role)
) STRICT;

CREATE TABLE account_security (
  account_id TEXT PRIMARY KEY NOT NULL CHECK(length(account_id) BETWEEN 1 AND 128),
  epoch INTEGER NOT NULL CHECK(epoch >= 0),
  active INTEGER NOT NULL CHECK(active IN (0, 1))
) STRICT;

CREATE TABLE admin_invitation_transaction (
  operation_id TEXT PRIMARY KEY NOT NULL CHECK(length(operation_id) = 43),
  account_id TEXT NOT NULL REFERENCES account_security(account_id),
  credential_id TEXT NOT NULL REFERENCES credential(credential_id),
  browser_hash TEXT NOT NULL CHECK(length(browser_hash) = 43),
  challenge TEXT NOT NULL CHECK(length(challenge) = 43),
  expires_at INTEGER NOT NULL CHECK(expires_at > 0),
  consumed INTEGER NOT NULL DEFAULT 0 CHECK(consumed IN (0, 1)),
  failures INTEGER NOT NULL DEFAULT 0 CHECK(failures BETWEEN 0 AND 5)
) STRICT;

CREATE TABLE agent_attribute_capability (
  grant_id TEXT PRIMARY KEY REFERENCES agent_grant(grant_id) ON DELETE CASCADE,
  attribute_id TEXT NOT NULL CHECK(attribute_id='owner_note'),
  base_revision INTEGER NOT NULL CHECK(base_revision>=0),
  grant_revision INTEGER NOT NULL,
  created_at INTEGER NOT NULL,
  expires_at INTEGER NOT NULL CHECK(expires_at>created_at AND expires_at<=created_at+3600)
, storage_version INTEGER NOT NULL DEFAULT 2 CHECK(storage_version IN(1,2)), target_origin TEXT, target_vault_id TEXT, target_collection_id TEXT, target_record_id TEXT, target_kind TEXT, target_ciphertext_sha256 TEXT, target_deleted INTEGER, target_key_generation INTEGER, target_owner_key_revision INTEGER);

CREATE TABLE agent_attribute_commit (
  proposal_id TEXT PRIMARY KEY REFERENCES agent_attribute_proposal(proposal_id) ON DELETE CASCADE,
  account_id TEXT NOT NULL REFERENCES account_security(account_id),
  operation_id TEXT NOT NULL,
  candidate TEXT NOT NULL,
  candidate_sha256 TEXT NOT NULL,
  origin TEXT NOT NULL,
  prepared_at INTEGER NOT NULL,
  result_revision INTEGER, storage_version INTEGER NOT NULL DEFAULT 2 CHECK(storage_version IN(1,2)),
  UNIQUE(account_id,operation_id)
) STRICT;

CREATE TABLE agent_attribute_commit_guard (
  operation_id TEXT PRIMARY KEY,
  valid INTEGER NOT NULL CHECK(valid=1)
) STRICT;

CREATE TABLE "agent_attribute_proposal" (
  proposal_id TEXT PRIMARY KEY,
  grant_id TEXT NOT NULL REFERENCES agent_grant(grant_id),
  grant_revision INTEGER NOT NULL,
  request_hash TEXT NOT NULL,
  attribute_id TEXT NOT NULL CHECK(attribute_id='owner_note'),
  base_revision INTEGER NOT NULL CHECK(base_revision>=0),
  payload TEXT,
  expires_at INTEGER NOT NULL,
  created_at INTEGER NOT NULL,
  state TEXT NOT NULL DEFAULT 'pending' CHECK(state IN('pending','approved','rejected','invalid','committed')), storage_version INTEGER NOT NULL DEFAULT 2 CHECK(storage_version IN(1,2)), target_origin TEXT, target_vault_id TEXT, target_collection_id TEXT, target_record_id TEXT, target_kind TEXT, target_ciphertext_sha256 TEXT, target_deleted INTEGER, target_key_generation INTEGER, target_owner_key_revision INTEGER,
  CHECK(expires_at>created_at AND expires_at<=created_at+3600)
);

CREATE TABLE agent_audit (
  event_id TEXT PRIMARY KEY,
  grant_id TEXT NOT NULL REFERENCES agent_grant(grant_id),
  operation TEXT NOT NULL,
  outcome TEXT NOT NULL,
  document_id TEXT,
  created_at INTEGER NOT NULL
);

CREATE TABLE agent_draft (
  draft_id TEXT PRIMARY KEY,
  account_id TEXT NOT NULL REFERENCES account_security(account_id),
  proposal_id TEXT NOT NULL UNIQUE REFERENCES agent_proposal(proposal_id),
  title TEXT NOT NULL,
  text TEXT NOT NULL,
  created_at INTEGER NOT NULL
);

CREATE TABLE agent_grant (
  grant_id TEXT PRIMARY KEY,
  account_id TEXT NOT NULL REFERENCES account_security(account_id),
  owner_epoch INTEGER NOT NULL,
  credential_id TEXT NOT NULL REFERENCES credential(credential_id),
  delegate TEXT NOT NULL,
  provider TEXT NOT NULL,
  resource TEXT NOT NULL,
  source_revision INTEGER NOT NULL,
  recipient_key_id TEXT NOT NULL,
  operations TEXT NOT NULL,
  document_ids TEXT NOT NULL,
  encrypted_snapshot TEXT,
  token_hash TEXT NOT NULL UNIQUE,
  request_hash TEXT NOT NULL,
  created_at INTEGER NOT NULL,
  expires_at INTEGER NOT NULL,
  revoked INTEGER NOT NULL DEFAULT 0 CHECK(revoked IN (0,1)),
  revision INTEGER NOT NULL DEFAULT 1 CHECK(revision > 0), storage_version INTEGER NOT NULL DEFAULT 2 CHECK(storage_version IN(1,2)), source_origin TEXT, source_vault_id TEXT, source_collection_id TEXT, source_record_id TEXT, source_kind TEXT, source_ciphertext_sha256 TEXT, source_key_generation INTEGER, source_owner_key_revision INTEGER,
  CHECK(expires_at > created_at AND expires_at <= created_at + 86400)
);

CREATE TABLE agent_oauth_client (
  client_id TEXT PRIMARY KEY,
  client_name TEXT NOT NULL,
  redirect_uris TEXT NOT NULL CHECK(json_valid(redirect_uris)),
  active INTEGER NOT NULL DEFAULT 1 CHECK(active IN(0,1))
) STRICT;

CREATE TABLE agent_oauth_guard (
  operation TEXT PRIMARY KEY,
  valid INTEGER NOT NULL CHECK(valid=1)
) STRICT;

CREATE TABLE agent_oauth_request (
  request_id TEXT PRIMARY KEY,
  client_id TEXT NOT NULL REFERENCES agent_oauth_client(client_id),
  redirect_uri TEXT NOT NULL,
  resource TEXT NOT NULL,
  scopes TEXT NOT NULL CHECK(json_valid(scopes)),
  state TEXT NOT NULL,
  challenge TEXT NOT NULL,
  created_at INTEGER NOT NULL,
  expires_at INTEGER NOT NULL,
  owner_account TEXT,
  owner_secret TEXT,
  grant_id TEXT REFERENCES agent_grant(grant_id),
  grant_revision INTEGER,
  decision TEXT CHECK(decision IN('approved','denied')),
  code_hash TEXT UNIQUE,
  code_expires_at INTEGER,
  redeemed_at INTEGER, owner_origin TEXT NOT NULL DEFAULT '', authorization_details TEXT
  CHECK(authorization_details IS NULL OR json_valid(authorization_details)),
  CHECK(expires_at=created_at+600),
  CHECK((owner_account IS NULL)=(owner_secret IS NULL)),
  CHECK((decision='approved' AND grant_id IS NOT NULL AND grant_revision IS NOT NULL
    AND code_hash IS NOT NULL AND code_expires_at IS NOT NULL)
    OR (decision IS NULL AND grant_id IS NULL AND grant_revision IS NULL AND code_hash IS NULL
      AND code_expires_at IS NULL AND redeemed_at IS NULL)
    OR (decision='denied' AND grant_id IS NULL AND code_hash IS NULL AND redeemed_at IS NULL))
) STRICT;

CREATE TABLE agent_oauth_token (
  token_hash TEXT PRIMARY KEY,
  request_id TEXT NOT NULL UNIQUE REFERENCES agent_oauth_request(request_id) ON DELETE CASCADE,
  client_id TEXT NOT NULL REFERENCES agent_oauth_client(client_id),
  grant_id TEXT NOT NULL REFERENCES agent_grant(grant_id),
  grant_revision INTEGER NOT NULL,
  resource TEXT NOT NULL,
  scopes TEXT NOT NULL CHECK(json_valid(scopes)),
  created_at INTEGER NOT NULL,
  expires_at INTEGER NOT NULL,
  revoked INTEGER NOT NULL DEFAULT 0 CHECK(revoked IN(0,1)), authorization_details TEXT
  CHECK(authorization_details IS NULL OR json_valid(authorization_details)),
  CHECK(expires_at>created_at AND expires_at<=created_at+3600)
) STRICT;

CREATE TABLE agent_proposal (
  proposal_id TEXT PRIMARY KEY,
  grant_id TEXT NOT NULL REFERENCES agent_grant(grant_id),
  request_hash TEXT NOT NULL,
  document_id TEXT NOT NULL,
  title TEXT NOT NULL,
  text TEXT,
  expires_at INTEGER NOT NULL,
  state TEXT NOT NULL DEFAULT 'pending' CHECK(state IN ('pending','approved','executed','rejected')),
  approved_revision INTEGER,
  result_id TEXT UNIQUE,
  created_at INTEGER NOT NULL
);

CREATE TABLE agent_recipient_key (
  key_id TEXT PRIMARY KEY,
  state TEXT NOT NULL CHECK(state IN('active','disabled'))
);

CREATE TABLE app_connection (
  account_id TEXT NOT NULL REFERENCES account_security(account_id),
  client_id TEXT NOT NULL REFERENCES client(client_id),
  grant_version INTEGER NOT NULL CHECK(grant_version >= 0),
  active INTEGER NOT NULL CHECK(active IN (0, 1)),
  PRIMARY KEY(account_id, client_id)
) STRICT;

CREATE TABLE assertion_use (
  client_id TEXT NOT NULL REFERENCES client(client_id),
  jti TEXT NOT NULL CHECK(length(jti) BETWEEN 1 AND 256),
  endpoint TEXT NOT NULL CHECK(length(endpoint) BETWEEN 1 AND 2048),
  accepted_by TEXT NOT NULL UNIQUE CHECK(length(accepted_by) BETWEEN 1 AND 128),
  retain_until INTEGER NOT NULL CHECK(retain_until > 0),
  PRIMARY KEY(client_id, jti)
) STRICT;

CREATE TABLE atomic_guard (
  operation_id TEXT PRIMARY KEY NOT NULL CHECK(length(operation_id) BETWEEN 1 AND 128),
  passed INTEGER NOT NULL CHECK(passed = 1)
) STRICT;

CREATE TABLE auth_request_window (
  key_hash TEXT NOT NULL,
  window_start INTEGER NOT NULL,
  attempts INTEGER NOT NULL CHECK(attempts>0),
  PRIMARY KEY(key_hash,window_start)
) STRICT;

CREATE TABLE auth_resource_policy (
  id INTEGER PRIMARY KEY CHECK(id=1),
  source_per_minute INTEGER NOT NULL CHECK(source_per_minute BETWEEN 1 AND 10000),
  deployment_per_minute INTEGER NOT NULL CHECK(deployment_per_minute BETWEEN 1 AND 10000),
  pending_per_browser INTEGER NOT NULL CHECK(pending_per_browser BETWEEN 2 AND 100),
  pending_per_client INTEGER NOT NULL CHECK(pending_per_client BETWEEN 10 AND 1000),
  pending_total INTEGER NOT NULL CHECK(pending_total BETWEEN 100 AND 10000)
) STRICT;

CREATE TABLE authorization_code (
  code_hash TEXT PRIMARY KEY NOT NULL CHECK(length(code_hash) = 43),
  client_id TEXT NOT NULL,
  sid TEXT NOT NULL,
  client_revision INTEGER NOT NULL CHECK(client_revision >= 0),
  redirect_uri TEXT NOT NULL CHECK(length(redirect_uri) BETWEEN 1 AND 2048),
  pkce_challenge TEXT NOT NULL CHECK(pkce_challenge = '' OR length(pkce_challenge) = 43),
  expires_at INTEGER NOT NULL CHECK(expires_at > 0),
  consumed_by TEXT UNIQUE,
  consumed_at INTEGER, dpop_jkt TEXT
  CHECK(dpop_jkt IS NULL OR length(dpop_jkt) = 43), redirect_uri_actual TEXT NOT NULL DEFAULT ''
  CHECK(redirect_uri_actual = '' OR length(redirect_uri_actual) BETWEEN 1 AND 2048),
  FOREIGN KEY(client_id, sid) REFERENCES client_session(client_id, sid),
  FOREIGN KEY(client_id, redirect_uri)
    REFERENCES client_redirect_uri(client_id, redirect_uri),
  CHECK((consumed_by IS NULL) = (consumed_at IS NULL))
) STRICT;

CREATE TABLE bootstrap_state (
  id INTEGER PRIMARY KEY NOT NULL CHECK(id = 1),
  closed INTEGER NOT NULL DEFAULT 0 CHECK(closed IN (0, 1))
) STRICT;

CREATE TABLE "client" (
  client_id TEXT PRIMARY KEY NOT NULL CHECK(length(client_id) BETWEEN 1 AND 128),
  revision INTEGER NOT NULL CHECK(revision >= 0),
  active INTEGER NOT NULL CHECK(active IN (0, 1)),
  client_type TEXT NOT NULL DEFAULT 'web' CHECK(client_type IN ('web', 'native')),
  auth_method TEXT NOT NULL DEFAULT 'private_key_jwt'
    CHECK(auth_method IN ('private_key_jwt', 'client_secret_basic', 'client_secret_post', 'none')),
  allow_missing_pkce INTEGER NOT NULL DEFAULT 0 CHECK(allow_missing_pkce IN (0, 1)),
  sector_identifier TEXT NOT NULL CHECK(length(sector_identifier) BETWEEN 1 AND 2048),
  CHECK(
    (client_type='native' AND auth_method='none' AND allow_missing_pkce=0) OR
    (client_type='web' AND auth_method!='none' AND
      (allow_missing_pkce=0 OR auth_method IN ('client_secret_basic','client_secret_post')))
  )
) STRICT;

CREATE TABLE "client_admin_audit" (
  operation_id TEXT PRIMARY KEY NOT NULL,
  client_id TEXT NOT NULL,
  action TEXT NOT NULL CHECK(action IN (
    'register', 'add-key', 'retire-key', 'add-redirect', 'retire-redirect',
    'add-post-logout-redirect', 'retire-post-logout-redirect',
    'set-backchannel-logout', 'retire-backchannel-logout', 'disable'
  )),
  actor TEXT NOT NULL,
  reason TEXT NOT NULL,
  occurred_at INTEGER NOT NULL CHECK(occurred_at > 0)
) STRICT;

CREATE TABLE "client_auth_use" (
  accepted_by TEXT PRIMARY KEY NOT NULL CHECK(length(accepted_by) BETWEEN 1 AND 128),
  client_id TEXT NOT NULL REFERENCES client(client_id),
  method TEXT NOT NULL
    CHECK(method IN ('private_key_jwt', 'client_secret_basic', 'client_secret_post', 'none')),
  endpoint TEXT NOT NULL CHECK(length(endpoint) BETWEEN 1 AND 2048),
  credential_id TEXT NOT NULL CHECK(length(credential_id) <= 128),
  client_revision INTEGER NOT NULL CHECK(client_revision >= 0),
  credential_revision INTEGER NOT NULL CHECK(credential_revision >= 0),
  retain_until INTEGER NOT NULL CHECK(retain_until > 0),
  CHECK(method!='none' OR (credential_id='' AND credential_revision=0))
) STRICT;

CREATE TABLE client_backchannel_logout_uri (
  client_id TEXT PRIMARY KEY NOT NULL REFERENCES client(client_id),
  logout_uri TEXT NOT NULL CHECK(length(logout_uri) BETWEEN 1 AND 2048),
  active INTEGER NOT NULL CHECK(active IN (0, 1))
) STRICT;

CREATE TABLE client_key (
  client_id TEXT NOT NULL REFERENCES client(client_id),
  kid TEXT NOT NULL CHECK(length(kid) BETWEEN 1 AND 128),
  revision INTEGER NOT NULL CHECK(revision >= 0),
  active INTEGER NOT NULL CHECK(active IN (0, 1)),
  algorithm TEXT NOT NULL CHECK(algorithm = 'ES256'),
  public_key_sec1 BLOB NOT NULL
    CHECK(typeof(public_key_sec1) = 'blob' AND length(public_key_sec1) IN (33, 65)),
  PRIMARY KEY(client_id, kid)
) STRICT;

CREATE TABLE client_post_logout_redirect_uri (
  client_id TEXT NOT NULL REFERENCES client(client_id),
  redirect_uri TEXT NOT NULL CHECK(length(redirect_uri) BETWEEN 1 AND 2048),
  active INTEGER NOT NULL CHECK(active IN (0, 1)),
  PRIMARY KEY(client_id, redirect_uri)
) STRICT;

CREATE TABLE client_redirect_uri (
  client_id TEXT NOT NULL REFERENCES client(client_id),
  redirect_uri TEXT NOT NULL CHECK(length(redirect_uri) BETWEEN 1 AND 2048), active INTEGER NOT NULL DEFAULT 1 CHECK(active IN (0, 1)),
  PRIMARY KEY(client_id, redirect_uri)
) STRICT;

CREATE TABLE client_secret (
  client_id TEXT PRIMARY KEY NOT NULL REFERENCES client(client_id),
  revision INTEGER NOT NULL CHECK(revision >= 0),
  active INTEGER NOT NULL CHECK(active IN (0, 1)),
  secret_hash TEXT NOT NULL CHECK(length(secret_hash) = 43)
) STRICT;

CREATE TABLE client_secret_attempt (
  client_id TEXT PRIMARY KEY NOT NULL REFERENCES client(client_id),
  window_start INTEGER NOT NULL CHECK(window_start > 0),
  attempts INTEGER NOT NULL CHECK(attempts BETWEEN 1 AND 1000)
) STRICT;

CREATE TABLE client_session (
  client_id TEXT NOT NULL,
  sid TEXT NOT NULL CHECK(length(sid) BETWEEN 1 AND 128),
  sso_id TEXT NOT NULL,
  account_id TEXT NOT NULL,
  sub TEXT NOT NULL CHECK(length(sub) BETWEEN 1 AND 255),
  grant_version INTEGER NOT NULL CHECK(grant_version >= 0),
  revoked INTEGER NOT NULL CHECK(revoked IN (0, 1)),
  PRIMARY KEY(client_id, sid),
  FOREIGN KEY(sso_id, account_id) REFERENCES sso_session(sso_id, account_id),
  FOREIGN KEY(account_id, client_id) REFERENCES app_connection(account_id, client_id)
) STRICT;

CREATE TABLE "code_context" (
  code_hash TEXT PRIMARY KEY NOT NULL REFERENCES authorization_code(code_hash),
  nonce TEXT CHECK(nonce IS NULL OR length(nonce) BETWEEN 1 AND 512),
  scope TEXT NOT NULL DEFAULT 'openid'
    CHECK(scope IN ('openid','openid profile','profile openid',
      'openid vault.read','vault.read openid'))
) STRICT;

CREATE TABLE credential (
  credential_id TEXT PRIMARY KEY NOT NULL CHECK(length(credential_id) BETWEEN 1 AND 512),
  account_id TEXT NOT NULL REFERENCES account_security(account_id),
  active INTEGER NOT NULL CHECK(active IN (0, 1)),
  UNIQUE(credential_id, account_id)
) STRICT;

CREATE TABLE dpop_nonce (
  scope TEXT NOT NULL CHECK(scope IN ('as', 'rs')),
  nonce TEXT NOT NULL UNIQUE CHECK(length(nonce) = 43),
  challenge_until INTEGER NOT NULL CHECK(challenge_until > 0),
  accept_until INTEGER NOT NULL CHECK(accept_until = challenge_until + 60),
  PRIMARY KEY(scope, nonce)
) STRICT;

CREATE TABLE dpop_proof_use (
  jkt TEXT NOT NULL CHECK(length(jkt) = 43),
  jti_hash TEXT NOT NULL CHECK(length(jti_hash) = 43),
  accepted_by TEXT NOT NULL UNIQUE CHECK(length(accepted_by) = 43),
  retain_until INTEGER NOT NULL CHECK(retain_until > 0),
  PRIMARY KEY(jkt, jti_hash)
) STRICT;

CREATE TABLE enrollment_invite (
  invite_hash TEXT PRIMARY KEY NOT NULL CHECK(length(invite_hash) = 43),
  kind TEXT NOT NULL CHECK(kind IN ('bootstrap', 'normal')),
  issuer_account_id TEXT REFERENCES account_security(account_id),
  issued_at INTEGER NOT NULL CHECK(issued_at > 0),
  expires_at INTEGER NOT NULL CHECK(expires_at > issued_at),
  consumed_at INTEGER CHECK(consumed_at IS NULL OR consumed_at >= issued_at),
  revoked INTEGER NOT NULL DEFAULT 0 CHECK(revoked IN (0, 1)),
  CHECK((kind = 'bootstrap') = (issuer_account_id IS NULL))
) STRICT;

CREATE TABLE enrollment_invite_audit (
  operation_id TEXT PRIMARY KEY NOT NULL,
  invite_hash TEXT NOT NULL REFERENCES enrollment_invite(invite_hash),
  action TEXT NOT NULL CHECK(action IN ('issue-bootstrap', 'issue-normal', 'revoke')),
  actor TEXT NOT NULL CHECK(length(actor) BETWEEN 1 AND 128),
  reason TEXT NOT NULL CHECK(length(reason) BETWEEN 1 AND 512),
  occurred_at INTEGER NOT NULL CHECK(occurred_at > 0)
) STRICT;

CREATE TABLE enrollment_policy (
  id INTEGER PRIMARY KEY NOT NULL CHECK(id = 1),
  bootstrap_ttl_seconds INTEGER NOT NULL CHECK(bootstrap_ttl_seconds BETWEEN 60 AND 86400),
  invite_ttl_seconds INTEGER NOT NULL CHECK(invite_ttl_seconds BETWEEN 3600 AND 604800),
  management_ttl_seconds INTEGER NOT NULL CHECK(management_ttl_seconds BETWEEN 60 AND 900),
  registration_ttl_seconds INTEGER NOT NULL CHECK(registration_ttl_seconds BETWEEN 60 AND 900),
  revision INTEGER NOT NULL CHECK(revision > 0)
) STRICT;

CREATE TABLE identity_attester_challenge (
  challenge_hash TEXT PRIMARY KEY NOT NULL,
  client_id TEXT NOT NULL,
  purpose TEXT NOT NULL CHECK(purpose IN ('client','holder')),
  policy_hash TEXT NOT NULL,
  client_binding TEXT,
  nonce_hash TEXT,
  expires_at INTEGER NOT NULL,
  used INTEGER NOT NULL DEFAULT 0 CHECK(used IN (0,1)),
  CHECK((purpose='client' AND client_binding IS NULL AND nonce_hash IS NULL)
     OR (purpose='holder' AND client_binding IS NOT NULL AND nonce_hash IS NOT NULL))
) STRICT;

CREATE TABLE identity_claim_release (
  account_id TEXT NOT NULL REFERENCES account_security(account_id),
  client_id TEXT NOT NULL REFERENCES client(client_id),
  document_id TEXT NOT NULL REFERENCES identity_document(document_id),
  epoch INTEGER NOT NULL,
  client_revision INTEGER NOT NULL,
  connection_grant_version INTEGER NOT NULL,
  fields_json TEXT NOT NULL CHECK(json_valid(fields_json) AND json_type(fields_json)='array'),
  expires_at INTEGER NOT NULL,
  version INTEGER NOT NULL CHECK(version>0),
  active INTEGER NOT NULL CHECK(active IN (0,1)),
  PRIMARY KEY(account_id,client_id)
) STRICT;

CREATE TABLE identity_document (
  document_id TEXT PRIMARY KEY NOT NULL REFERENCES identity_transaction(tx_id),
  account_id TEXT NOT NULL REFERENCES account_security(account_id),
  epoch INTEGER NOT NULL,
  document_json TEXT NOT NULL CHECK(json_valid(document_json)),
  policy_hash TEXT NOT NULL,
  linked_at INTEGER NOT NULL,
  valid_until INTEGER NOT NULL,
  revoked INTEGER NOT NULL DEFAULT 0 CHECK(revoked IN (0,1))
) STRICT;

CREATE TABLE identity_nonce (
  nonce_hash TEXT PRIMARY KEY NOT NULL,
  expires_at INTEGER NOT NULL,
  used INTEGER NOT NULL DEFAULT 0 CHECK(used IN (0,1))
) STRICT;

CREATE TABLE identity_transaction (
  tx_id TEXT PRIMARY KEY NOT NULL,
  poll_hash TEXT UNIQUE NOT NULL,
  holder_json TEXT NOT NULL CHECK(json_valid(holder_json)),
  document_json TEXT NOT NULL CHECK(json_valid(document_json)),
  policy_hash TEXT NOT NULL,
  created_at INTEGER NOT NULL,
  expires_at INTEGER NOT NULL,
  state TEXT NOT NULL CHECK(state IN ('pending','approved','denied','offered','token','issued')),
  account_id TEXT REFERENCES account_security(account_id),
  epoch INTEGER,
  session_hash TEXT,
  csrf_hash TEXT,
  offer_hash TEXT UNIQUE,
  access_hash TEXT UNIQUE,
  token_expires_at INTEGER,
  proof_nonce_hash TEXT
) STRICT;

CREATE TABLE identity_wallet_attestation_replay (
  replay_hash TEXT PRIMARY KEY NOT NULL,
  expires_at INTEGER NOT NULL
) STRICT;

CREATE TABLE identity_wallet_grant (
  grant_id TEXT PRIMARY KEY NOT NULL,
  document_id TEXT REFERENCES identity_document(document_id),
  account_id TEXT NOT NULL REFERENCES account_security(account_id),
  epoch INTEGER NOT NULL,
  session_hash TEXT NOT NULL,
  csrf_hash TEXT,
  client_id TEXT NOT NULL,
  client_policy_hash TEXT NOT NULL,
  policy_hash TEXT NOT NULL,
  redirect_uri TEXT NOT NULL,
  wallet_state TEXT,
  code_challenge TEXT NOT NULL,
  configuration TEXT NOT NULL CHECK(configuration IN ('linked_document','linked_document_mdoc')),
  state TEXT NOT NULL CHECK(state IN ('pending','offered','denied','token','issued')),
  expires_at INTEGER NOT NULL,
  code_hash TEXT UNIQUE,
  access_hash TEXT UNIQUE,
  token_expires_at INTEGER,
  holder_json TEXT CHECK(holder_json IS NULL OR json_valid(holder_json)),
  proof_nonce_hash TEXT
, par_hash TEXT, dpop_jkt TEXT, client_binding TEXT, authorization_dpop_jkt TEXT
  CHECK(authorization_dpop_jkt IS NULL OR length(authorization_dpop_jkt)=43), redeemed_code_hash TEXT, issuance_limit INTEGER NOT NULL DEFAULT 1 CHECK(issuance_limit IN (1,16)), issuance_count INTEGER NOT NULL DEFAULT 0 CHECK(issuance_count>=0 AND issuance_count<=issuance_limit)) STRICT;

CREATE TABLE identity_wallet_par (
  request_hash TEXT PRIMARY KEY NOT NULL,
  client_id TEXT NOT NULL,
  client_policy_hash TEXT NOT NULL,
  request_json TEXT NOT NULL CHECK(json_valid(request_json)),
  expires_at INTEGER NOT NULL,
  used INTEGER NOT NULL DEFAULT 0 CHECK(used IN (0,1))
, client_binding TEXT, redirect_uri TEXT, wallet_state TEXT) STRICT;

CREATE TABLE login_transaction (
  tx_id TEXT PRIMARY KEY NOT NULL CHECK(length(tx_id) = 43),
  browser_hash TEXT NOT NULL CHECK(length(browser_hash) = 43),
  authorization_url TEXT NOT NULL CHECK(length(authorization_url) BETWEEN 1 AND 8192),
  client_id TEXT NOT NULL REFERENCES client(client_id),
  challenge TEXT NOT NULL CHECK(length(challenge) = 43),
  expires_at INTEGER NOT NULL CHECK(expires_at > 0),
  consumed INTEGER NOT NULL DEFAULT 0 CHECK(consumed IN (0, 1)),
  failures INTEGER NOT NULL DEFAULT 0 CHECK(failures BETWEEN 0 AND 5)
) STRICT;

CREATE TABLE logout_delivery (
  event_id TEXT NOT NULL REFERENCES sso_logout_event(event_id),
  client_id TEXT NOT NULL REFERENCES client(client_id),
  sid TEXT NOT NULL CHECK(length(sid) BETWEEN 1 AND 128),
  sub TEXT NOT NULL CHECK(length(sub) BETWEEN 1 AND 255),
  logout_uri TEXT NOT NULL CHECK(length(logout_uri) BETWEEN 1 AND 2048),
  state TEXT NOT NULL DEFAULT 'pending'
    CHECK(state IN ('pending', 'leased', 'delivered', 'failed', 'expired')),
  attempts INTEGER NOT NULL DEFAULT 0 CHECK(attempts >= 0),
  next_at INTEGER NOT NULL CHECK(next_at > 0),
  lease_id TEXT,
  lease_until INTEGER,
  last_status INTEGER,
  finished_at INTEGER,
  PRIMARY KEY(event_id, client_id, sid),
  CHECK((state = 'leased') = (lease_id IS NOT NULL AND lease_until IS NOT NULL))
) STRICT;

CREATE TABLE logout_transaction (
  csrf_hash TEXT PRIMARY KEY NOT NULL CHECK(length(csrf_hash) = 43),
  sso_id TEXT NOT NULL REFERENCES sso_session(sso_id),
  cookie_hash TEXT NOT NULL CHECK(length(cookie_hash) = 43),
  redirect_uri TEXT NOT NULL CHECK(length(redirect_uri) <= 2048),
  state TEXT NOT NULL CHECK(length(state) <= 2048),
  expires_at INTEGER NOT NULL CHECK(expires_at > 0)
) STRICT;

CREATE TABLE owner_login_transaction (
  tx_id TEXT PRIMARY KEY NOT NULL CHECK(length(tx_id)=43),
  browser_hash TEXT NOT NULL CHECK(length(browser_hash)=43),
  request_id TEXT NOT NULL REFERENCES agent_oauth_request(request_id) ON DELETE CASCADE,
  authorization_url TEXT NOT NULL,
  challenge TEXT NOT NULL CHECK(length(challenge)=43),
  expires_at INTEGER NOT NULL,
  consumed INTEGER NOT NULL DEFAULT 0 CHECK(consumed IN(0,1)),
  failures INTEGER NOT NULL DEFAULT 0 CHECK(failures BETWEEN 0 AND 5)
) STRICT;

CREATE TABLE owner_passkey_registration (
  transaction_id TEXT PRIMARY KEY CHECK(length(transaction_id)=43),
  account_id TEXT NOT NULL REFERENCES account_security(account_id),
  session_hash TEXT NOT NULL,
  challenge TEXT NOT NULL,
  user_handle TEXT NOT NULL,
  expires_at INTEGER NOT NULL,
  failures INTEGER NOT NULL DEFAULT 0 CHECK(failures BETWEEN 0 AND 5),
  credential_id TEXT,
  request_hash TEXT,
  consumed INTEGER NOT NULL DEFAULT 0 CHECK(consumed IN(0,1))
) STRICT;

CREATE TABLE pairwise_subject (
  account_id TEXT NOT NULL REFERENCES account_security(account_id),
  sector_identifier TEXT NOT NULL CHECK(length(sector_identifier) BETWEEN 1 AND 2048),
  sub TEXT NOT NULL UNIQUE CHECK(length(sub) BETWEEN 1 AND 255),
  PRIMARY KEY(account_id, sector_identifier)
) STRICT;

CREATE TABLE par_request (
  request_uri TEXT PRIMARY KEY NOT NULL CHECK(length(request_uri) BETWEEN 50 AND 256),
  client_id TEXT NOT NULL REFERENCES client(client_id),
  client_revision INTEGER NOT NULL CHECK(client_revision >= 0),
  key_id TEXT NOT NULL CHECK(length(key_id) BETWEEN 1 AND 128),
  key_revision INTEGER NOT NULL CHECK(key_revision >= 0),
  request_query TEXT NOT NULL CHECK(length(request_query) BETWEEN 1 AND 8192),
  dpop_jkt TEXT CHECK(dpop_jkt IS NULL OR length(dpop_jkt) = 43),
  expires_at INTEGER NOT NULL CHECK(expires_at > 0),
  consumed_by TEXT UNIQUE REFERENCES authorization_code(code_hash) ON DELETE SET NULL,
  FOREIGN KEY(client_id,key_id) REFERENCES client_key(client_id,kid)
) STRICT;

CREATE TABLE passkey_credential (
  credential_id TEXT PRIMARY KEY NOT NULL REFERENCES credential(credential_id),
  public_key TEXT NOT NULL CHECK(length(public_key) BETWEEN 1 AND 4096),
  user_handle TEXT NOT NULL CHECK(length(user_handle) BETWEEN 1 AND 128),
  counter INTEGER NOT NULL CHECK(counter BETWEEN 0 AND 4294967295),
  backup_eligible INTEGER NOT NULL CHECK(backup_eligible IN (0, 1)),
  backup_state INTEGER NOT NULL CHECK(backup_state IN (0, 1)),
  revision INTEGER NOT NULL CHECK(revision >= 0)
) STRICT;

CREATE TABLE registration_transaction (
  tx_id TEXT PRIMARY KEY NOT NULL REFERENCES login_transaction(tx_id),
  browser_hash TEXT NOT NULL CHECK(length(browser_hash) = 43),
  invite_hash TEXT NOT NULL REFERENCES enrollment_invite(invite_hash),
  challenge TEXT NOT NULL CHECK(length(challenge) = 43),
  user_handle TEXT NOT NULL CHECK(length(user_handle) = 43),
  expires_at INTEGER NOT NULL CHECK(expires_at > 0),
  consumed INTEGER NOT NULL DEFAULT 0 CHECK(consumed IN (0, 1)),
  failures INTEGER NOT NULL DEFAULT 0 CHECK(failures BETWEEN 0 AND 5)
) STRICT;

CREATE TABLE revocation_event (
  operation_id TEXT PRIMARY KEY NOT NULL CHECK(length(operation_id) BETWEEN 1 AND 128),
  account_id TEXT NOT NULL REFERENCES account_security(account_id),
  through_epoch INTEGER NOT NULL CHECK(through_epoch >= 0),
  created_at INTEGER NOT NULL CHECK(created_at > 0)
) STRICT;

CREATE TABLE runtime_policy_active (
  id INTEGER PRIMARY KEY NOT NULL CHECK(id = 1),
  projection_revision TEXT NOT NULL REFERENCES runtime_policy_version(projection_revision),
  generation INTEGER NOT NULL CHECK(generation > 0)
) STRICT;

CREATE TABLE runtime_policy_audit (
  generation INTEGER PRIMARY KEY NOT NULL CHECK(generation > 0),
  previous_revision TEXT,
  projection_revision TEXT NOT NULL REFERENCES runtime_policy_version(projection_revision),
  changed_at INTEGER NOT NULL CHECK(changed_at > 0),
  actor TEXT NOT NULL CHECK(length(actor) BETWEEN 1 AND 128),
  reason TEXT NOT NULL CHECK(length(reason) BETWEEN 1 AND 512)
) STRICT;

CREATE TABLE runtime_policy_version (
  projection_revision TEXT PRIMARY KEY NOT NULL CHECK(length(projection_revision) = 64),
  policy_revision TEXT NOT NULL CHECK(length(policy_revision) = 64),
  projection_json TEXT NOT NULL CHECK(length(projection_json) BETWEEN 1 AND 16384),
  created_at INTEGER NOT NULL CHECK(created_at > 0)
) STRICT;

CREATE TABLE session_validation_policy (
  id INTEGER PRIMARY KEY NOT NULL CHECK(id=1),
  lease_ttl_seconds INTEGER NOT NULL CHECK(lease_ttl_seconds BETWEEN 1 AND 300),
  app_idle_timeout_seconds INTEGER NOT NULL CHECK(app_idle_timeout_seconds BETWEEN 60 AND 2592000),
  revision INTEGER NOT NULL CHECK(revision > 0)
) STRICT;

CREATE TABLE signing_key (
  kid TEXT PRIMARY KEY NOT NULL CHECK(length(kid) BETWEEN 1 AND 128),
  generation INTEGER NOT NULL CHECK(generation >= 0),
  active INTEGER NOT NULL CHECK(active IN (0, 1)),
  algorithm TEXT NOT NULL CHECK(algorithm IN ('ES256', 'RS256')),
  public_jwk TEXT NOT NULL CHECK(length(public_jwk) BETWEEN 1 AND 2048)
) STRICT;

CREATE TABLE sso_context (
  sso_id TEXT PRIMARY KEY NOT NULL REFERENCES sso_session(sso_id),
  secret_hash TEXT NOT NULL UNIQUE CHECK(length(secret_hash) BETWEEN 1 AND 128),
  auth_time INTEGER NOT NULL CHECK(auth_time > 0)
) STRICT;

CREATE TABLE sso_logout_event (
  event_id TEXT PRIMARY KEY NOT NULL CHECK(length(event_id) = 43),
  sso_id TEXT NOT NULL UNIQUE REFERENCES sso_session(sso_id),
  created_at INTEGER NOT NULL CHECK(created_at > 0),
  deadline INTEGER NOT NULL CHECK(deadline > created_at)
) STRICT;

CREATE TABLE sso_session (
  sso_id TEXT PRIMARY KEY NOT NULL CHECK(length(sso_id) BETWEEN 1 AND 128),
  account_id TEXT NOT NULL REFERENCES account_security(account_id),
  credential_id TEXT NOT NULL,
  epoch INTEGER NOT NULL CHECK(epoch >= 0),
  expires_at INTEGER NOT NULL CHECK(expires_at > 0),
  revoked INTEGER NOT NULL CHECK(revoked IN (0, 1)),
  FOREIGN KEY(credential_id, account_id) REFERENCES credential(credential_id, account_id),
  UNIQUE(sso_id, account_id)
) STRICT;

CREATE TABLE token_issue (
  code_hash TEXT PRIMARY KEY NOT NULL REFERENCES authorization_code(code_hash),
  operation_id TEXT NOT NULL UNIQUE CHECK(length(operation_id) BETWEEN 1 AND 128),
  access_hash TEXT NOT NULL UNIQUE CHECK(length(access_hash) = 43),
  access_expires_at INTEGER NOT NULL CHECK(access_expires_at > 0),
  signing_kid TEXT NOT NULL REFERENCES signing_key(kid),
  issued_at INTEGER NOT NULL CHECK(issued_at > 0),
  revoked INTEGER NOT NULL CHECK(revoked IN (0, 1))
, id_token_hash TEXT
  CHECK(id_token_hash IS NULL OR length(id_token_hash) = 43), dpop_jkt TEXT
  CHECK(dpop_jkt IS NULL OR length(dpop_jkt) = 43)) STRICT;

CREATE TABLE vault_claim_disclosure_audit (
  id INTEGER PRIMARY KEY,
  account_id TEXT NOT NULL,
  client_id TEXT NOT NULL,
  claim TEXT NOT NULL CHECK(claim='name'),
  attribute_revision INTEGER NOT NULL CHECK(attribute_revision>0),
  release_version INTEGER NOT NULL CHECK(release_version>0),
  occurred_at INTEGER NOT NULL CHECK(occurred_at>0)
, source_storage_version INTEGER NOT NULL DEFAULT 2 CHECK(source_storage_version=2), source_json TEXT) STRICT;

CREATE TABLE vault_claim_release (
  account_id TEXT NOT NULL,
  client_id TEXT NOT NULL,
  claim TEXT NOT NULL CHECK(claim = 'name'),
  attribute_revision INTEGER NOT NULL CHECK(attribute_revision > 0),
  system_grant_version INTEGER NOT NULL CHECK(system_grant_version > 0),
  client_revision INTEGER NOT NULL CHECK(client_revision >= 0),
  connection_grant_version INTEGER NOT NULL CHECK(connection_grant_version >= 0),
  version INTEGER NOT NULL CHECK(version > 0),
  status TEXT NOT NULL CHECK(status IN ('active','revoked')),
  expires_at INTEGER NOT NULL CHECK(expires_at > 0),
  updated_at INTEGER NOT NULL CHECK(updated_at > 0), source_storage_version INTEGER NOT NULL DEFAULT 2 CHECK(source_storage_version=2), source_origin TEXT, source_vault_id TEXT, source_collection_id TEXT, source_record_id TEXT, source_kind TEXT, source_ciphertext_sha256 TEXT, source_key_generation INTEGER, source_owner_key_revision INTEGER,
  PRIMARY KEY(account_id,client_id,claim),
  FOREIGN KEY(account_id,client_id) REFERENCES app_connection(account_id,client_id)
) STRICT;

CREATE TABLE vault_claim_release_atomic_guard (
  operation_id TEXT PRIMARY KEY,
  passed INTEGER NOT NULL CHECK(passed=1)
) STRICT;

CREATE TABLE vault_claim_release_audit (
  account_id TEXT NOT NULL,
  operation_id TEXT NOT NULL CHECK(length(operation_id)=43),
  request_hash TEXT NOT NULL CHECK(length(request_hash)=43),
  client_id TEXT NOT NULL,
  claim TEXT NOT NULL CHECK(claim='name'),
  action TEXT NOT NULL CHECK(action IN ('grant','revoke')),
  release_version INTEGER NOT NULL CHECK(release_version>0),
  occurred_at INTEGER NOT NULL CHECK(occurred_at>0), source_storage_version INTEGER NOT NULL DEFAULT 2 CHECK(source_storage_version=2), source_json TEXT,
  PRIMARY KEY(account_id,operation_id)
) STRICT;

CREATE TABLE vault_claim_release_policy (
  id INTEGER PRIMARY KEY CHECK(id = 1),
  enabled INTEGER NOT NULL CHECK(enabled IN (0, 1)),
  ttl_seconds INTEGER NOT NULL CHECK(ttl_seconds BETWEEN 60 AND 2592000),
  revision INTEGER NOT NULL CHECK(revision > 0)
) STRICT;

CREATE TABLE vault_gc_candidate (
  object_key TEXT PRIMARY KEY NOT NULL,
  eligible_at INTEGER NOT NULL,
  state TEXT NOT NULL DEFAULT 'pending' CHECK(state IN ('pending','deleting'))
) STRICT;

CREATE TABLE vault_owner_key_head (
  account_id TEXT PRIMARY KEY NOT NULL REFERENCES account_security(account_id),
  vault_id TEXT NOT NULL CHECK(length(vault_id) BETWEEN 1 AND 128),
  origin TEXT NOT NULL,
  key_generation INTEGER NOT NULL CHECK(key_generation BETWEEN 1 AND 9007199254740991),
  revision INTEGER NOT NULL CHECK(revision BETWEEN 1 AND 9007199254740991),
  format_version INTEGER NOT NULL CHECK(format_version=2),
  suite TEXT NOT NULL,
  operation_id TEXT NOT NULL CHECK(length(operation_id)=43),
  request_hash TEXT NOT NULL CHECK(length(request_hash)=43),
  created_at INTEGER NOT NULL,
  UNIQUE(account_id,key_generation)
) STRICT;

CREATE TABLE vault_owner_key_wrap (
  account_id TEXT NOT NULL,
  key_generation INTEGER NOT NULL,
  credential_id TEXT NOT NULL,
  envelope TEXT NOT NULL CHECK(length(envelope) BETWEEN 1 AND 2048),
  PRIMARY KEY(account_id,key_generation,credential_id),
  FOREIGN KEY(account_id,key_generation) REFERENCES vault_owner_key_head(account_id,key_generation),
  FOREIGN KEY(credential_id,account_id) REFERENCES credential(credential_id,account_id)
) STRICT;

CREATE TABLE vault_owner_record_gc_cursor (
  id INTEGER PRIMARY KEY CHECK(id=1),
  cursor TEXT
) STRICT;

CREATE TABLE vault_owner_record_head (
  account_id TEXT NOT NULL,
  vault_id TEXT NOT NULL,
  collection_id TEXT NOT NULL CHECK(length(collection_id) BETWEEN 1 AND 128),
  record_id TEXT NOT NULL CHECK(length(record_id) BETWEEN 1 AND 128),
  kind TEXT NOT NULL CHECK(length(kind) BETWEEN 1 AND 128),
  revision INTEGER NOT NULL CHECK(revision BETWEEN 1 AND 9007199254740991),
  key_generation INTEGER NOT NULL CHECK(key_generation BETWEEN 1 AND 9007199254740991),
  format_version INTEGER NOT NULL CHECK(format_version=2),
  object_key TEXT,
  ciphertext_sha256 TEXT,
  key_envelope TEXT,
  deleted INTEGER NOT NULL CHECK(deleted IN (0,1)),
  updated_at INTEGER NOT NULL,
  PRIMARY KEY(account_id,vault_id,collection_id,record_id),
  FOREIGN KEY(account_id,vault_id) REFERENCES vault_owner_key_head(account_id,vault_id),
  CHECK((deleted=1 AND object_key IS NULL AND ciphertext_sha256 IS NULL AND key_envelope IS NULL)
    OR (deleted=0 AND object_key IS NOT NULL AND ciphertext_sha256 IS NOT NULL AND key_envelope IS NOT NULL AND length(ciphertext_sha256)=43 AND length(key_envelope)=82))
) STRICT;

CREATE TABLE vault_owner_record_mutation (
  account_id TEXT NOT NULL REFERENCES account_security(account_id),
  operation_id TEXT NOT NULL CHECK(length(operation_id)=43),
  request_hash TEXT NOT NULL CHECK(length(request_hash)=43),
  result_revision INTEGER NOT NULL CHECK(result_revision BETWEEN 1 AND 9007199254740991),
  deleted INTEGER NOT NULL CHECK(deleted IN (0,1)),
  created_at INTEGER NOT NULL,
  PRIMARY KEY(account_id,operation_id)
) STRICT;

CREATE TABLE vault_recipient_atomic_guard (
  operation_id TEXT PRIMARY KEY,
  passed INTEGER NOT NULL CHECK(passed = 1)
) STRICT;

CREATE TABLE vault_recipient_key (
  key_id TEXT PRIMARY KEY CHECK(length(key_id) = 43),
  service_id TEXT NOT NULL CHECK(service_id = 'userinfo'),
  algorithm TEXT NOT NULL CHECK(algorithm = 'ML-KEM-768'),
  public_key BLOB NOT NULL CHECK(length(public_key) = 1184),
  secret_ref TEXT NOT NULL UNIQUE CHECK(length(secret_ref) BETWEEN 1 AND 128),
  generation INTEGER NOT NULL CHECK(generation > 0),
  state TEXT NOT NULL CHECK(state IN ('staged', 'active', 'decrypt_only', 'disabled')),
  revision INTEGER NOT NULL CHECK(revision > 0),
  created_at INTEGER NOT NULL CHECK(created_at > 0),
  activated_at INTEGER CHECK(activated_at > 0),
  retired_at INTEGER CHECK(retired_at > 0),
  UNIQUE(service_id, generation),
  CHECK((state = 'staged' AND activated_at IS NULL AND retired_at IS NULL)
     OR (state = 'active' AND activated_at IS NOT NULL AND retired_at IS NULL)
     OR (state = 'decrypt_only' AND activated_at IS NOT NULL AND retired_at IS NOT NULL)
     OR (state = 'disabled' AND retired_at IS NOT NULL))
) STRICT;

CREATE TABLE vault_recipient_key_audit (
  operation_id TEXT PRIMARY KEY NOT NULL,
  key_id TEXT NOT NULL REFERENCES vault_recipient_key(key_id),
  action TEXT NOT NULL CHECK(action IN ('stage', 'activate', 'rotate', 'disable')),
  actor TEXT NOT NULL CHECK(length(actor) BETWEEN 1 AND 128),
  reason TEXT NOT NULL CHECK(length(reason) BETWEEN 1 AND 512),
  revision INTEGER NOT NULL CHECK(revision > 0),
  occurred_at INTEGER NOT NULL CHECK(occurred_at > 0)
) STRICT;

CREATE TABLE vault_record_grant (
 account_id TEXT NOT NULL, origin TEXT NOT NULL, vault_id TEXT NOT NULL,
 collection_id TEXT NOT NULL CHECK(collection_id='personal'),
 record_id TEXT NOT NULL CHECK(record_id='name'),kind TEXT NOT NULL CHECK(kind='name'),
 record_revision INTEGER NOT NULL CHECK(record_revision BETWEEN 1 AND 9007199254740991),
 ciphertext_sha256 TEXT NOT NULL CHECK(length(ciphertext_sha256)=43),
 key_generation INTEGER NOT NULL CHECK(key_generation BETWEEN 1 AND 9007199254740991),
 owner_key_revision INTEGER NOT NULL CHECK(owner_key_revision BETWEEN 1 AND 9007199254740991),
 recipient_service TEXT NOT NULL CHECK(recipient_service='userinfo'),
 purpose TEXT NOT NULL CHECK(purpose='oidc.userinfo.name'),envelope_id TEXT NOT NULL,
 version INTEGER NOT NULL CHECK(version BETWEEN 1 AND 9007199254740991),status TEXT NOT NULL CHECK(status IN ('active','revoked')),
 expires_at INTEGER NOT NULL CHECK(expires_at>0),updated_at INTEGER NOT NULL CHECK(updated_at>0),
 PRIMARY KEY(account_id,vault_id,collection_id,record_id,recipient_service,purpose),
 FOREIGN KEY(envelope_id,account_id,origin,vault_id,collection_id,record_id,kind,record_revision,
  ciphertext_sha256,key_generation,owner_key_revision,recipient_service,purpose)
 REFERENCES vault_record_recipient_envelope(envelope_id,account_id,origin,vault_id,collection_id,record_id,kind,
  record_revision,ciphertext_sha256,key_generation,owner_key_revision,recipient_service,purpose)
) STRICT;

CREATE TABLE vault_record_recipient_envelope (
 envelope_id TEXT PRIMARY KEY NOT NULL CHECK(length(envelope_id)=43),
 account_id TEXT NOT NULL, origin TEXT NOT NULL, vault_id TEXT NOT NULL,
 collection_id TEXT NOT NULL CHECK(collection_id='personal'),
 record_id TEXT NOT NULL CHECK(record_id='name'), kind TEXT NOT NULL CHECK(kind='name'),
 record_revision INTEGER NOT NULL CHECK(record_revision BETWEEN 1 AND 9007199254740991),
 ciphertext_sha256 TEXT NOT NULL CHECK(length(ciphertext_sha256)=43),
 key_generation INTEGER NOT NULL CHECK(key_generation BETWEEN 1 AND 9007199254740991),
 owner_key_revision INTEGER NOT NULL CHECK(owner_key_revision BETWEEN 1 AND 9007199254740991),
 recipient_service TEXT NOT NULL CHECK(recipient_service='userinfo'),
 purpose TEXT NOT NULL CHECK(purpose='oidc.userinfo.name'),
 recipient_key_id TEXT NOT NULL REFERENCES vault_recipient_key(key_id),
 recipient_generation INTEGER NOT NULL CHECK(recipient_generation BETWEEN 1 AND 9007199254740991),
 directory_revision INTEGER NOT NULL CHECK(directory_revision BETWEEN 1 AND 9007199254740991),
 policy_revision INTEGER NOT NULL CHECK(policy_revision BETWEEN 1 AND 9007199254740991),
 suite TEXT NOT NULL CHECK(suite='ML-KEM-768-HKDF-SHA256-AES-256-GCM-draft04-record-v2'),
 frame BLOB NOT NULL CHECK(length(frame)=1187 AND hex(substr(frame,1,5))='4D4B565202'),
 created_at INTEGER NOT NULL CHECK(created_at>0),
 FOREIGN KEY(account_id,vault_id,collection_id,record_id)
  REFERENCES vault_owner_record_head(account_id,vault_id,collection_id,record_id),
 UNIQUE(envelope_id,account_id),
 UNIQUE(envelope_id,account_id,origin,vault_id,collection_id,record_id,kind,record_revision,
  ciphertext_sha256,key_generation,owner_key_revision,recipient_service,purpose)
) STRICT;

CREATE TABLE vault_record_share_audit (
 account_id TEXT NOT NULL,operation_id TEXT NOT NULL CHECK(length(operation_id)=43),
 request_hash TEXT NOT NULL CHECK(length(request_hash)=43),action TEXT NOT NULL CHECK(action IN ('share','revoke')),
 envelope_id TEXT NOT NULL,
 grant_version INTEGER NOT NULL CHECK(grant_version>0),occurred_at INTEGER NOT NULL CHECK(occurred_at>0),
 PRIMARY KEY(account_id,operation_id),
 FOREIGN KEY(envelope_id,account_id) REFERENCES vault_record_recipient_envelope(envelope_id,account_id)
) STRICT;

CREATE TABLE vault_record_share_guard (
 account_id TEXT NOT NULL,operation_id TEXT NOT NULL,passed INTEGER NOT NULL CHECK(passed=1),
 PRIMARY KEY(account_id,operation_id)
) STRICT;

CREATE TABLE vault_record_share_policy (
 id INTEGER PRIMARY KEY CHECK(id=1), enabled INTEGER NOT NULL CHECK(enabled IN (0,1)),
 grant_ttl_seconds INTEGER NOT NULL CHECK(grant_ttl_seconds BETWEEN 60 AND 2592000),
 revision INTEGER NOT NULL CHECK(revision>0)
) STRICT;

CREATE TABLE web_login_transaction (
  tx_id TEXT PRIMARY KEY NOT NULL CHECK(length(tx_id)=43),
  browser_hash TEXT NOT NULL CHECK(length(browser_hash)=43),
  authorization_url TEXT NOT NULL,
  challenge TEXT NOT NULL CHECK(length(challenge)=43),
  expires_at INTEGER NOT NULL,
  consumed INTEGER NOT NULL DEFAULT 0 CHECK(consumed IN(0,1)),
  failures INTEGER NOT NULL DEFAULT 0 CHECK(failures BETWEEN 0 AND 5)
) STRICT;

CREATE INDEX agent_attribute_proposal_grant ON agent_attribute_proposal(grant_id,created_at);

CREATE INDEX agent_audit_recent ON agent_audit(grant_id,created_at);

CREATE INDEX agent_grant_owner ON agent_grant(account_id,created_at);

CREATE INDEX agent_oauth_pending ON agent_oauth_request(client_id,expires_at);

CREATE INDEX assertion_gc ON assertion_use(retain_until);

CREATE INDEX auth_window_expiry ON auth_request_window(window_start);

CREATE INDEX client_auth_gc ON client_auth_use(retain_until);

CREATE INDEX client_session_sso ON client_session(sso_id, client_id, sid);

CREATE INDEX code_expiry ON authorization_code(expires_at);

CREATE INDEX dpop_nonce_expiry ON dpop_nonce(accept_until);

CREATE INDEX dpop_proof_use_expiry ON dpop_proof_use(retain_until);

CREATE INDEX identity_attester_challenge_expiry ON identity_attester_challenge(expires_at);

CREATE INDEX identity_document_owner ON identity_document(account_id);

CREATE INDEX identity_transaction_expiry ON identity_transaction(expires_at);

CREATE INDEX identity_wallet_attestation_replay_expiry ON identity_wallet_attestation_replay(expires_at);

CREATE INDEX identity_wallet_grant_document ON identity_wallet_grant(document_id);

CREATE INDEX identity_wallet_grant_expiry ON identity_wallet_grant(expires_at);

CREATE INDEX identity_wallet_par_expiry ON identity_wallet_par(expires_at);

CREATE UNIQUE INDEX identity_wallet_redeemed_code ON identity_wallet_grant(redeemed_code_hash);

CREATE INDEX login_browser_pending ON login_transaction(browser_hash,consumed,expires_at);

CREATE INDEX login_client_pending ON login_transaction(client_id,consumed,expires_at);

CREATE INDEX login_expiry ON login_transaction(expires_at);

CREATE INDEX login_pending ON login_transaction(consumed,expires_at);

CREATE INDEX logout_delivery_due ON logout_delivery(state, next_at);

CREATE INDEX logout_event_deadline ON sso_logout_event(deadline);

CREATE INDEX logout_transaction_expiry ON logout_transaction(expires_at);

CREATE UNIQUE INDEX one_open_bootstrap_invite ON enrollment_invite(kind)
  WHERE kind='bootstrap' AND consumed_at IS NULL AND revoked=0;

CREATE INDEX owner_login_browser_pending ON owner_login_transaction(browser_hash,consumed,expires_at);

CREATE INDEX owner_login_expiry ON owner_login_transaction(expires_at);

CREATE INDEX owner_login_pending ON owner_login_transaction(consumed,expires_at);

CREATE INDEX owner_login_request ON owner_login_transaction(request_id,expires_at);

CREATE INDEX owner_passkey_registration_expiry ON owner_passkey_registration(expires_at);

CREATE INDEX par_request_expiry ON par_request(expires_at);

CREATE INDEX registration_expiry ON registration_transaction(expires_at);

CREATE INDEX sso_account_epoch ON sso_session(account_id, epoch);

CREATE INDEX sso_expiry ON sso_session(expires_at);

CREATE INDEX token_expiry ON token_issue(access_expires_at);

CREATE INDEX token_issue_id_token_hash ON token_issue(id_token_hash)
  WHERE id_token_hash IS NOT NULL;

CREATE INDEX vault_gc_candidate_due ON vault_gc_candidate(eligible_at,object_key);

CREATE UNIQUE INDEX vault_owner_key_identity ON vault_owner_key_head(account_id,vault_id);

CREATE UNIQUE INDEX vault_owner_record_object ON vault_owner_record_head(object_key) WHERE object_key IS NOT NULL;

CREATE INDEX vault_owner_record_rate ON vault_owner_record_mutation(account_id,created_at);

CREATE INDEX vault_owner_record_retention ON vault_owner_record_mutation(created_at);

CREATE UNIQUE INDEX vault_recipient_one_active
  ON vault_recipient_key(service_id) WHERE state = 'active';

CREATE INDEX web_login_browser_pending ON web_login_transaction(browser_hash,consumed,expires_at);

CREATE INDEX web_login_expiry ON web_login_transaction(expires_at);

CREATE INDEX web_login_pending ON web_login_transaction(consumed,expires_at);

CREATE VIEW eligible_client_session AS
SELECT cs.client_id, cs.sid, cs.sub, ss.expires_at, ss.account_id
FROM client_session cs
JOIN sso_session ss ON ss.sso_id = cs.sso_id AND ss.account_id = cs.account_id
JOIN account_security a ON a.account_id = ss.account_id
JOIN credential cr ON cr.credential_id = ss.credential_id AND cr.account_id = a.account_id
JOIN client c ON c.client_id = cs.client_id
JOIN app_connection g ON g.account_id = cs.account_id AND g.client_id = cs.client_id
WHERE a.active = 1 AND a.epoch = ss.epoch AND cr.active = 1
  AND c.active = 1 AND g.active = 1 AND g.grant_version = cs.grant_version
  AND ss.revoked = 0 AND cs.revoked = 0
  AND ss.expires_at > CAST(strftime('%s', 'now') AS INTEGER);

CREATE VIEW valid_client_session AS
SELECT v.* FROM eligible_client_session v
WHERE EXISTS (
  SELECT 1 FROM authorization_code ac JOIN token_issue ti ON ti.code_hash = ac.code_hash
  WHERE ac.client_id = v.client_id AND ac.sid = v.sid
    AND ac.consumed_by = ti.operation_id AND ac.consumed_at IS NOT NULL AND ti.revoked = 0
);

CREATE TRIGGER agent_attribute_capability_immutable BEFORE UPDATE ON agent_attribute_capability
BEGIN SELECT RAISE(ABORT,'capability must be reissued on a new grant'); END;

CREATE TRIGGER agent_attribute_capability_source BEFORE INSERT ON agent_attribute_capability
WHEN COALESCE((
 (NEW.storage_version=1 AND EXISTS(SELECT 1 FROM agent_grant g WHERE g.grant_id=NEW.grant_id AND g.storage_version=1)
  AND NEW.target_origin IS NULL AND NEW.target_vault_id IS NULL AND NEW.target_collection_id IS NULL
  AND NEW.target_record_id IS NULL AND NEW.target_kind IS NULL AND NEW.target_ciphertext_sha256 IS NULL
  AND NEW.target_deleted IS NULL AND NEW.target_key_generation IS NULL AND NEW.target_owner_key_revision IS NULL)
 OR (NEW.storage_version=2 AND EXISTS(SELECT 1 FROM agent_grant g WHERE g.grant_id=NEW.grant_id AND g.storage_version=2)
  AND NEW.target_origin IS NOT NULL AND length(NEW.target_origin)>8 AND substr(NEW.target_origin,1,8)='https://'
  AND NEW.target_vault_id IS NOT NULL AND length(NEW.target_vault_id) BETWEEN 1 AND 128
  AND NEW.target_vault_id NOT GLOB '*[^A-Za-z0-9_-]*'
  AND NEW.target_collection_id='personal' AND NEW.target_record_id='owner_note' AND NEW.target_kind='owner_note'
  AND typeof(NEW.base_revision)='integer' AND NEW.base_revision BETWEEN 0 AND 9007199254740990
  AND typeof(NEW.target_deleted)='integer' AND NEW.target_deleted IN(0,1)
  AND typeof(NEW.target_key_generation)='integer' AND NEW.target_key_generation BETWEEN 1 AND 9007199254740991
  AND typeof(NEW.target_owner_key_revision)='integer' AND NEW.target_owner_key_revision BETWEEN 1 AND 9007199254740991
  AND ((NEW.base_revision=0 AND NEW.target_deleted=0 AND NEW.target_ciphertext_sha256 IS NULL)
    OR (NEW.base_revision>0 AND ((NEW.target_deleted=1 AND NEW.target_ciphertext_sha256 IS NULL)
      OR (NEW.target_deleted=0 AND NEW.target_ciphertext_sha256 IS NOT NULL
       AND length(NEW.target_ciphertext_sha256)=43 AND NEW.target_ciphertext_sha256 NOT GLOB '*[^A-Za-z0-9_-]*')))))
),0)=0
BEGIN SELECT RAISE(ABORT,'invalid record capability target'); END;

CREATE TRIGGER agent_attribute_commit_source BEFORE INSERT ON agent_attribute_commit
WHEN NEW.result_revision IS NOT NULL OR NOT EXISTS(
 SELECT 1 FROM agent_attribute_proposal p JOIN agent_grant g ON g.grant_id=p.grant_id
 WHERE p.proposal_id=NEW.proposal_id AND p.storage_version=NEW.storage_version
 AND g.storage_version=NEW.storage_version AND g.account_id=NEW.account_id
 AND p.state='approved' AND p.payload IS NOT NULL
 AND (NEW.storage_version=1 OR (p.target_origin=NEW.origin AND json_valid(NEW.candidate)
   AND json_extract(NEW.candidate,'$.format_version')=2
   AND json_extract(NEW.candidate,'$.vault_id')=p.target_vault_id
   AND json_extract(NEW.candidate,'$.kind')=p.target_kind
   AND json_extract(NEW.candidate,'$.revision')=p.base_revision+1
   AND json_extract(NEW.candidate,'$.key_generation')=p.target_key_generation
   AND json_extract(NEW.candidate,'$.owner_key_revision')=p.target_owner_key_revision)))
BEGIN SELECT RAISE(ABORT,'prepared commit source mismatch'); END;

CREATE TRIGGER agent_attribute_proposal_decision_audit AFTER UPDATE OF state ON agent_attribute_proposal
WHEN NEW.state!=OLD.state
BEGIN
  INSERT INTO agent_audit VALUES('attribute:' || NEW.proposal_id || ':' || NEW.state,
    NEW.grant_id,'attribute-decision',NEW.state,NEW.attribute_id,unixepoch());
END;

CREATE TRIGGER agent_attribute_proposal_grant_stop AFTER UPDATE OF revoked ON agent_grant
WHEN NEW.revoked=1
BEGIN
  UPDATE agent_attribute_proposal SET state='invalid',payload=NULL
    WHERE grant_id=NEW.grant_id AND state IN('pending','approved');
END;

CREATE TRIGGER agent_attribute_proposal_immutable BEFORE UPDATE ON agent_attribute_proposal
WHEN NEW.proposal_id!=OLD.proposal_id OR NEW.grant_id!=OLD.grant_id
 OR NEW.grant_revision!=OLD.grant_revision OR NEW.request_hash!=OLD.request_hash
 OR NEW.attribute_id!=OLD.attribute_id OR NEW.base_revision!=OLD.base_revision
 OR NEW.expires_at!=OLD.expires_at OR NEW.created_at!=OLD.created_at
 OR (NEW.payload IS NOT OLD.payload AND NEW.payload IS NOT NULL)
 OR (NEW.state!=OLD.state AND NOT(
   (OLD.state='pending' AND NEW.state IN('approved','rejected','invalid'))
   OR (OLD.state='approved' AND NEW.state IN('invalid','committed'))))
BEGIN SELECT RAISE(ABORT,'invalid attribute proposal transition'); END;

CREATE TRIGGER agent_attribute_proposal_record_delete AFTER DELETE ON vault_owner_record_head
BEGIN
 UPDATE agent_attribute_proposal SET state='invalid',payload=NULL
 WHERE storage_version=2 AND grant_id IN(SELECT grant_id FROM agent_grant WHERE account_id=OLD.account_id)
   AND target_vault_id=OLD.vault_id AND target_collection_id=OLD.collection_id AND target_record_id=OLD.record_id
   AND state IN('pending','approved');
END;

CREATE TRIGGER agent_attribute_proposal_record_immutable BEFORE UPDATE ON agent_attribute_proposal
WHEN NEW.storage_version IS NOT OLD.storage_version OR NEW.target_origin IS NOT OLD.target_origin
 OR NEW.target_vault_id IS NOT OLD.target_vault_id OR NEW.target_collection_id IS NOT OLD.target_collection_id
 OR NEW.target_record_id IS NOT OLD.target_record_id OR NEW.target_kind IS NOT OLD.target_kind
 OR NEW.target_ciphertext_sha256 IS NOT OLD.target_ciphertext_sha256 OR NEW.target_deleted IS NOT OLD.target_deleted
 OR NEW.target_key_generation IS NOT OLD.target_key_generation OR NEW.target_owner_key_revision IS NOT OLD.target_owner_key_revision
BEGIN SELECT RAISE(ABORT,'record proposal target is immutable'); END;

CREATE TRIGGER agent_attribute_proposal_record_insert AFTER INSERT ON vault_owner_record_head
BEGIN
 UPDATE agent_attribute_proposal SET state='invalid',payload=NULL
 WHERE storage_version=2 AND grant_id IN(SELECT grant_id FROM agent_grant WHERE account_id=NEW.account_id)
   AND target_vault_id=NEW.vault_id AND target_collection_id=NEW.collection_id AND target_record_id=NEW.record_id
   AND state IN('pending','approved') AND (base_revision!=NEW.revision OR target_deleted!=NEW.deleted
     OR target_ciphertext_sha256 IS NOT NEW.ciphertext_sha256 OR target_kind IS NOT NEW.kind
     OR NEW.format_version!=2 OR target_key_generation!=NEW.key_generation);
END;

CREATE TRIGGER agent_attribute_proposal_record_update AFTER UPDATE ON vault_owner_record_head
BEGIN
 UPDATE agent_attribute_proposal SET state='invalid',payload=NULL
 WHERE storage_version=2 AND grant_id IN(SELECT grant_id FROM agent_grant WHERE account_id=OLD.account_id)
   AND target_vault_id=OLD.vault_id AND target_collection_id=OLD.collection_id AND target_record_id=OLD.record_id
   AND state IN('pending','approved') AND (base_revision!=NEW.revision OR target_deleted!=NEW.deleted
     OR target_ciphertext_sha256 IS NOT NEW.ciphertext_sha256 OR target_kind IS NOT NEW.kind
     OR target_vault_id IS NOT NEW.vault_id OR target_collection_id IS NOT NEW.collection_id OR target_record_id IS NOT NEW.record_id
     OR OLD.account_id IS NOT NEW.account_id OR NEW.format_version!=2 OR target_key_generation!=NEW.key_generation);
END;

CREATE TRIGGER agent_attribute_proposal_target_shape BEFORE INSERT ON agent_attribute_proposal
WHEN COALESCE((
 (NEW.storage_version=1 AND EXISTS(SELECT 1 FROM agent_grant g WHERE g.grant_id=NEW.grant_id AND g.storage_version=1)
  AND NEW.target_origin IS NULL AND NEW.target_vault_id IS NULL AND NEW.target_collection_id IS NULL
  AND NEW.target_record_id IS NULL AND NEW.target_kind IS NULL AND NEW.target_ciphertext_sha256 IS NULL
  AND NEW.target_deleted IS NULL AND NEW.target_key_generation IS NULL AND NEW.target_owner_key_revision IS NULL)
 OR (NEW.storage_version=2 AND NEW.state='pending' AND NEW.payload IS NOT NULL
  AND EXISTS(SELECT 1 FROM agent_attribute_capability c JOIN agent_grant g ON g.grant_id=c.grant_id
   WHERE c.grant_id=NEW.grant_id AND g.storage_version=2
   AND c.storage_version=NEW.storage_version AND c.attribute_id=NEW.attribute_id AND c.base_revision=NEW.base_revision
   AND c.grant_revision=NEW.grant_revision AND c.expires_at>=NEW.expires_at
   AND c.target_origin IS NEW.target_origin AND c.target_vault_id IS NEW.target_vault_id
   AND c.target_collection_id IS NEW.target_collection_id AND c.target_record_id IS NEW.target_record_id
   AND c.target_kind IS NEW.target_kind AND c.target_ciphertext_sha256 IS NEW.target_ciphertext_sha256
   AND c.target_deleted IS NEW.target_deleted AND c.target_key_generation IS NEW.target_key_generation
   AND c.target_owner_key_revision IS NEW.target_owner_key_revision))
),0)=0
BEGIN SELECT RAISE(ABORT,'record proposal target requires exact capability'); END;

CREATE TRIGGER agent_grant_account_stop AFTER UPDATE OF active,epoch ON account_security
WHEN NEW.active=0 OR NEW.epoch!=OLD.epoch
BEGIN
  UPDATE agent_grant SET revoked=1,revision=revision+1,encrypted_snapshot=NULL
  WHERE account_id=NEW.account_id AND revoked=0 AND (NEW.active=0 OR owner_epoch!=NEW.epoch);
END;

CREATE TRIGGER agent_grant_credential_stop AFTER UPDATE OF active ON credential
WHEN NEW.active=0
BEGIN
  UPDATE agent_grant SET revoked=1,revision=revision+1,encrypted_snapshot=NULL
  WHERE credential_id=NEW.credential_id AND revoked=0;
END;

CREATE TRIGGER agent_grant_owner_key_change AFTER UPDATE ON vault_owner_key_head
WHEN NEW.account_id IS NOT OLD.account_id OR NEW.vault_id IS NOT OLD.vault_id
  OR NEW.origin IS NOT OLD.origin OR NEW.key_generation IS NOT OLD.key_generation
  OR NEW.revision IS NOT OLD.revision OR NEW.format_version IS NOT OLD.format_version
  OR NEW.suite IS NOT OLD.suite
BEGIN
  UPDATE agent_grant SET revoked=1,revision=revision+1,encrypted_snapshot=NULL
  WHERE storage_version=2 AND account_id=OLD.account_id AND source_vault_id=OLD.vault_id AND revoked=0;
END;

CREATE TRIGGER agent_grant_owner_key_delete AFTER DELETE ON vault_owner_key_head
BEGIN
  UPDATE agent_grant SET revoked=1,revision=revision+1,encrypted_snapshot=NULL
  WHERE storage_version=2 AND account_id=OLD.account_id AND source_vault_id=OLD.vault_id AND revoked=0;
END;

CREATE TRIGGER agent_grant_record_change AFTER UPDATE ON vault_owner_record_head
WHEN NEW.account_id IS NOT OLD.account_id OR NEW.vault_id IS NOT OLD.vault_id
  OR NEW.collection_id IS NOT OLD.collection_id OR NEW.record_id IS NOT OLD.record_id
  OR NEW.kind IS NOT OLD.kind OR NEW.revision IS NOT OLD.revision
  OR NEW.ciphertext_sha256 IS NOT OLD.ciphertext_sha256 OR NEW.key_generation IS NOT OLD.key_generation
  OR NEW.format_version IS NOT OLD.format_version OR NEW.deleted=1
BEGIN
  UPDATE agent_grant SET revoked=1,revision=revision+1,encrypted_snapshot=NULL
  WHERE storage_version=2 AND account_id=OLD.account_id AND source_vault_id=OLD.vault_id
    AND source_collection_id=OLD.collection_id AND source_record_id=OLD.record_id AND revoked=0;
END;

CREATE TRIGGER agent_grant_record_delete AFTER DELETE ON vault_owner_record_head
BEGIN
  UPDATE agent_grant SET revoked=1,revision=revision+1,encrypted_snapshot=NULL
  WHERE storage_version=2 AND account_id=OLD.account_id AND source_vault_id=OLD.vault_id
    AND source_collection_id=OLD.collection_id AND source_record_id=OLD.record_id AND revoked=0;
END;

CREATE TRIGGER agent_grant_revoked AFTER UPDATE OF revoked ON agent_grant
WHEN OLD.revoked=0 AND NEW.revoked=1
BEGIN
  INSERT INTO agent_audit VALUES('invalidate:' || NEW.grant_id || ':' || NEW.revision,
    NEW.grant_id,'invalidate','revoked',NULL,unixepoch());
  UPDATE agent_proposal SET text=NULL,state='rejected'
  WHERE grant_id=NEW.grant_id AND state IN('pending','approved');
END;

CREATE TRIGGER agent_grant_snapshot_clear AFTER UPDATE OF revoked ON agent_grant
WHEN NEW.revoked=1 AND NEW.encrypted_snapshot IS NOT NULL
BEGIN
  UPDATE agent_grant SET encrypted_snapshot=NULL WHERE grant_id=NEW.grant_id;
END;

CREATE TRIGGER agent_grant_source_immutable BEFORE UPDATE ON agent_grant
WHEN NEW.storage_version IS NOT OLD.storage_version OR NEW.account_id IS NOT OLD.account_id
  OR NEW.document_ids IS NOT OLD.document_ids
  OR NEW.source_revision IS NOT OLD.source_revision OR NEW.source_origin IS NOT OLD.source_origin
  OR NEW.source_vault_id IS NOT OLD.source_vault_id OR NEW.source_collection_id IS NOT OLD.source_collection_id
  OR NEW.source_record_id IS NOT OLD.source_record_id OR NEW.source_kind IS NOT OLD.source_kind
  OR NEW.source_ciphertext_sha256 IS NOT OLD.source_ciphertext_sha256
  OR NEW.source_key_generation IS NOT OLD.source_key_generation
  OR NEW.source_owner_key_revision IS NOT OLD.source_owner_key_revision
  OR (NEW.encrypted_snapshot IS NOT OLD.encrypted_snapshot AND NEW.encrypted_snapshot IS NOT NULL)
  OR (OLD.revoked=1 AND NEW.revoked!=1)
BEGIN SELECT RAISE(ABORT,'agent source is immutable and cannot be restored'); END;

CREATE TRIGGER agent_grant_source_shape BEFORE INSERT ON agent_grant
WHEN COALESCE((
  (NEW.storage_version=1 AND NEW.source_origin IS NULL AND NEW.source_vault_id IS NULL
    AND NEW.source_collection_id IS NULL AND NEW.source_record_id IS NULL AND NEW.source_kind IS NULL
    AND NEW.source_ciphertext_sha256 IS NULL AND NEW.source_key_generation IS NULL
    AND NEW.source_owner_key_revision IS NULL)
  OR (NEW.storage_version=2 AND NEW.source_origin IS NOT NULL AND NEW.source_vault_id IS NOT NULL
    AND NEW.source_collection_id='personal' AND NEW.source_record_id IN('name','owner_note')
    AND NEW.source_kind=NEW.source_record_id AND NEW.source_ciphertext_sha256 IS NOT NULL
    AND length(NEW.source_ciphertext_sha256)=43
    AND typeof(NEW.source_key_generation)='integer' AND NEW.source_key_generation BETWEEN 1 AND 9007199254740991
    AND typeof(NEW.source_owner_key_revision)='integer' AND NEW.source_owner_key_revision BETWEEN 1 AND 9007199254740991
    AND typeof(NEW.source_revision)='integer' AND NEW.source_revision BETWEEN 1 AND 9007199254740991
    AND json_valid(NEW.document_ids) AND json_array_length(NEW.document_ids)=1
    AND json_extract(NEW.document_ids,'$[0]')=NEW.source_record_id)
),0)=0
BEGIN SELECT RAISE(ABORT,'invalid agent source'); END;

CREATE TRIGGER agent_oauth_approval_audit AFTER UPDATE OF decision ON agent_oauth_request
WHEN OLD.decision IS NULL AND NEW.decision='approved'
BEGIN INSERT INTO agent_audit VALUES('oauth-consent:' || NEW.request_id,NEW.grant_id,
  'oauth-consent','approved',NULL,unixepoch()); END;

CREATE TRIGGER agent_oauth_client_immutable BEFORE UPDATE ON agent_oauth_client
WHEN OLD.active=0 OR NEW.client_id!=OLD.client_id OR NEW.client_name!=OLD.client_name
  OR NEW.redirect_uris!=OLD.redirect_uris OR NEW.active!=0
BEGIN SELECT RAISE(ABORT,'client registration is immutable; disable and replace'); END;

CREATE TRIGGER agent_oauth_client_no_delete BEFORE DELETE ON agent_oauth_client
BEGIN SELECT RAISE(ABORT,'client tombstone must be retained'); END;

CREATE TRIGGER agent_oauth_request_details_immutable BEFORE UPDATE OF authorization_details ON agent_oauth_request
BEGIN SELECT RAISE(ABORT,'authorization details are immutable'); END;

CREATE TRIGGER agent_oauth_revoke_audit AFTER UPDATE OF revoked ON agent_oauth_token
WHEN OLD.revoked=0 AND NEW.revoked=1
BEGIN INSERT INTO agent_audit VALUES('oauth-revoke:' || NEW.request_id,NEW.grant_id,
  'oauth-token','revoked',NULL,unixepoch()); END;

CREATE TRIGGER agent_oauth_token_audit AFTER INSERT ON agent_oauth_token
BEGIN INSERT INTO agent_audit VALUES('oauth-token:' || NEW.request_id,NEW.grant_id,
  'oauth-token','issued',NULL,unixepoch()); END;

CREATE TRIGGER agent_recipient_no_delete BEFORE DELETE ON agent_recipient_key
BEGIN SELECT RAISE(ABORT,'recipient key tombstone must be retained'); END;

CREATE TRIGGER agent_recipient_no_restore BEFORE UPDATE ON agent_recipient_key
WHEN OLD.state='disabled' OR NEW.key_id!=OLD.key_id
BEGIN SELECT RAISE(ABORT,'recipient key cannot be restored or replaced'); END;

CREATE TRIGGER agent_recipient_stop AFTER UPDATE OF state ON agent_recipient_key
WHEN NEW.state='disabled'
BEGIN
  UPDATE agent_grant SET revoked=1,revision=revision+1,encrypted_snapshot=NULL
  WHERE recipient_key_id=NEW.key_id AND revoked=0;
END;

CREATE TRIGGER authorization_code_actual_redirect_immutable
BEFORE UPDATE OF redirect_uri_actual ON authorization_code
WHEN NEW.redirect_uri_actual IS NOT OLD.redirect_uri_actual
BEGIN SELECT RAISE(ABORT, 'authorization-code redirect is immutable'); END;

CREATE TRIGGER authorization_code_dpop_binding_immutable BEFORE UPDATE OF dpop_jkt ON authorization_code
WHEN OLD.dpop_jkt IS NOT NULL AND NEW.dpop_jkt IS NOT OLD.dpop_jkt
BEGIN SELECT RAISE(ABORT, 'authorization-code DPoP binding is immutable'); END;

CREATE TRIGGER client_registration_revision BEFORE UPDATE ON client
WHEN NEW.revision <= OLD.revision
BEGIN SELECT RAISE(ABORT, 'client revision must increase'); END;

CREATE TRIGGER client_secret_revision BEFORE UPDATE ON client_secret
WHEN NEW.revision <= OLD.revision
BEGIN SELECT RAISE(ABORT, 'client secret revision must increase'); END;

CREATE TRIGGER code_context_scope_immutable BEFORE UPDATE OF scope ON code_context
BEGIN SELECT RAISE(ABORT, 'authorization scope is immutable'); END;

CREATE TRIGGER enrollment_invite_audit_no_delete BEFORE DELETE ON enrollment_invite_audit
BEGIN SELECT RAISE(ABORT, 'invite audit is immutable'); END;

CREATE TRIGGER enrollment_invite_audit_no_update BEFORE UPDATE ON enrollment_invite_audit
BEGIN SELECT RAISE(ABORT, 'invite audit is immutable'); END;

CREATE TRIGGER identity_approve_guard BEFORE UPDATE OF state ON identity_transaction
WHEN NEW.state='approved' AND OLD.state='pending'
BEGIN
  SELECT (CASE WHEN NOT EXISTS (
    SELECT 1 FROM sso_context sx JOIN sso_session ss ON ss.sso_id=sx.sso_id
    JOIN account_security a ON a.account_id=ss.account_id
    JOIN credential c ON c.credential_id=ss.credential_id AND c.account_id=ss.account_id
    WHERE sx.secret_hash=NEW.session_hash AND ss.account_id=NEW.account_id
      AND a.active=1 AND a.epoch=ss.epoch AND NEW.epoch=a.epoch
      AND ss.revoked=0 AND ss.expires_at>unixepoch() AND c.active=1
  ) THEN RAISE(ABORT,'identity approval preconditions failed') END);
END;

CREATE TRIGGER identity_consume_nonce AFTER UPDATE OF state ON identity_transaction
WHEN NEW.state='issued'
BEGIN
  UPDATE identity_nonce SET used=1 WHERE nonce_hash=NEW.proof_nonce_hash;
END;

CREATE TRIGGER identity_erase AFTER UPDATE OF revoked ON identity_document
WHEN NEW.revoked=1
BEGIN
  UPDATE identity_transaction SET document_json='{}',poll_hash=tx_id,offer_hash=NULL,access_hash=NULL,csrf_hash=NULL
  WHERE tx_id=NEW.document_id;
END;

CREATE TRIGGER identity_issue_guard BEFORE UPDATE OF state ON identity_transaction
WHEN NEW.state='issued'
BEGIN
  SELECT (CASE WHEN OLD.state!='token' OR NOT EXISTS (
    SELECT 1 FROM identity_nonce n WHERE n.nonce_hash=NEW.proof_nonce_hash
      AND n.used=0 AND n.expires_at>unixepoch()
  ) OR NOT EXISTS (
    SELECT 1 FROM identity_document d JOIN account_security a ON a.account_id=d.account_id
    WHERE d.document_id=NEW.tx_id AND d.revoked=0 AND d.valid_until>unixepoch()
      AND a.active=1 AND a.epoch=d.epoch AND a.epoch=NEW.epoch
  ) THEN RAISE(ABORT,'identity issuance preconditions failed') END);
END;

CREATE TRIGGER identity_link AFTER UPDATE OF state ON identity_transaction
WHEN NEW.state='approved' AND OLD.state='pending'
BEGIN
  INSERT INTO identity_document(document_id,account_id,epoch,document_json,policy_hash,linked_at,valid_until)
  VALUES(NEW.tx_id,NEW.account_id,NEW.epoch,NEW.document_json,NEW.policy_hash,unixepoch(),unixepoch()+86400);
END;

CREATE TRIGGER identity_release_account_change AFTER UPDATE OF active,epoch ON account_security
WHEN NEW.active!=OLD.active OR NEW.epoch!=OLD.epoch
BEGIN
  UPDATE identity_claim_release SET active=0,fields_json='[]',version=version+1
  WHERE account_id=NEW.account_id AND active=1;
END;

CREATE TRIGGER identity_release_client_change AFTER UPDATE ON client
BEGIN
  UPDATE identity_claim_release SET active=0,fields_json='[]',version=version+1
  WHERE client_id=NEW.client_id AND active=1;
END;

CREATE TRIGGER identity_release_connection_change AFTER UPDATE ON app_connection
BEGIN
  UPDATE identity_claim_release SET active=0,fields_json='[]',version=version+1
  WHERE account_id=NEW.account_id AND client_id=NEW.client_id AND active=1;
END;

CREATE TRIGGER identity_release_erase AFTER UPDATE OF revoked ON identity_document
WHEN NEW.revoked=1
BEGIN
  UPDATE identity_claim_release SET active=0,fields_json='[]',version=version+1 WHERE document_id=NEW.document_id;
END;

CREATE TRIGGER identity_wallet_account_change AFTER UPDATE ON account_security
WHEN NEW.active!=OLD.active OR NEW.epoch!=OLD.epoch
BEGIN
  DELETE FROM identity_wallet_grant WHERE account_id=NEW.account_id;
END;

CREATE TRIGGER identity_wallet_approval_guard BEFORE UPDATE OF state ON identity_wallet_grant
WHEN NEW.state IN ('offered','denied')
BEGIN
  SELECT (CASE WHEN OLD.state!='pending' OR NOT EXISTS (
    SELECT 1 FROM sso_context sx JOIN sso_session ss ON ss.sso_id=sx.sso_id
    JOIN account_security a ON a.account_id=ss.account_id
    JOIN credential c ON c.credential_id=ss.credential_id AND c.account_id=ss.account_id
    WHERE sx.secret_hash=NEW.session_hash AND ss.account_id=NEW.account_id
      AND a.active=1 AND a.epoch=ss.epoch AND NEW.epoch=a.epoch
      AND ss.revoked=0 AND ss.expires_at>unixepoch() AND c.active=1
  ) THEN RAISE(ABORT,'identity wallet approval preconditions failed') END);
END;

CREATE TRIGGER identity_wallet_attestation_copy AFTER INSERT ON identity_wallet_grant
WHEN NEW.par_hash IS NOT NULL
BEGIN
  UPDATE identity_wallet_grant SET client_binding=(SELECT client_binding FROM identity_wallet_par WHERE request_hash=NEW.par_hash) WHERE grant_id=NEW.grant_id;
END;

CREATE TRIGGER identity_wallet_consume_nonce AFTER UPDATE OF issuance_count ON identity_wallet_grant
BEGIN
  UPDATE identity_nonce SET used=1 WHERE nonce_hash=NEW.proof_nonce_hash;
END;

CREATE TRIGGER identity_wallet_erase AFTER UPDATE OF revoked ON identity_document
WHEN NEW.revoked=1
BEGIN
  DELETE FROM identity_wallet_grant WHERE document_id=NEW.document_id;
END;

CREATE TRIGGER identity_wallet_issue_guard BEFORE UPDATE OF issuance_count ON identity_wallet_grant
BEGIN
  SELECT (CASE WHEN OLD.state!='token' OR NEW.issuance_limit!=OLD.issuance_limit
    OR NEW.issuance_count!=OLD.issuance_count+1
    OR OLD.token_expires_at<=unixepoch() OR OLD.token_expires_at IS NULL
    OR NEW.token_expires_at IS NOT OLD.token_expires_at
    OR NEW.holder_json IS NULL
    OR (NEW.issuance_count<NEW.issuance_limit AND (NEW.state!='token' OR NEW.access_hash IS NOT OLD.access_hash))
    OR (NEW.issuance_count=NEW.issuance_limit AND (NEW.state!='issued' OR NEW.access_hash IS NOT NULL))
    OR NOT EXISTS (
      SELECT 1 FROM identity_nonce n WHERE n.nonce_hash=NEW.proof_nonce_hash
        AND n.used=0 AND n.expires_at>unixepoch()
    ) OR NOT EXISTS (
      SELECT 1 FROM identity_document d JOIN account_security a ON a.account_id=d.account_id
      WHERE d.document_id=NEW.document_id AND d.account_id=NEW.account_id
        AND d.revoked=0 AND d.valid_until>unixepoch() AND d.policy_hash=NEW.policy_hash
        AND a.active=1 AND a.epoch=d.epoch AND a.epoch=NEW.epoch
    ) THEN RAISE(ABORT,'identity wallet issuance preconditions failed') END);
END;

CREATE TRIGGER identity_wallet_par_consume AFTER UPDATE OF state ON identity_wallet_grant
WHEN OLD.state='pending' AND NEW.state IN ('offered','denied') AND NEW.par_hash IS NOT NULL
BEGIN
  UPDATE identity_wallet_par SET used=1,request_json='{}' WHERE request_hash=NEW.par_hash;
END;

CREATE TRIGGER identity_wallet_par_guard BEFORE INSERT ON identity_wallet_grant
WHEN NEW.par_hash IS NOT NULL
BEGIN
  SELECT (CASE WHEN NOT EXISTS (
    SELECT 1 FROM identity_wallet_par p WHERE p.request_hash=NEW.par_hash
      AND p.client_id=NEW.client_id AND p.client_policy_hash=NEW.client_policy_hash
      AND p.used=0 AND p.expires_at>unixepoch()
  ) THEN RAISE(ABORT,'identity PAR preconditions failed') END);
END;

CREATE TRIGGER login_transaction_capacity BEFORE INSERT ON login_transaction
WHEN (SELECT count(*) FROM login_transaction WHERE consumed=0 AND expires_at>unixepoch()) >= (SELECT pending_total FROM auth_resource_policy WHERE id=1)
 OR (SELECT count(*) FROM login_transaction WHERE browser_hash=NEW.browser_hash AND consumed=0 AND expires_at>unixepoch()) >= (SELECT pending_per_browser FROM auth_resource_policy WHERE id=1)
 OR (SELECT count(*) FROM login_transaction WHERE client_id=NEW.client_id AND consumed=0 AND expires_at>unixepoch()) >= (SELECT pending_per_client FROM auth_resource_policy WHERE id=1)
BEGIN SELECT RAISE(ABORT,'auth_capacity_exceeded'); END;

CREATE TRIGGER owner_login_transaction_capacity BEFORE INSERT ON owner_login_transaction
WHEN (SELECT count(*) FROM owner_login_transaction WHERE consumed=0 AND expires_at>unixepoch()) >= (SELECT pending_total FROM auth_resource_policy WHERE id=1)
 OR (SELECT count(*) FROM owner_login_transaction WHERE browser_hash=NEW.browser_hash AND consumed=0 AND expires_at>unixepoch()) >= (SELECT pending_per_browser FROM auth_resource_policy WHERE id=1)
BEGIN SELECT RAISE(ABORT,'auth_capacity_exceeded'); END;

CREATE TRIGGER runtime_policy_audit_no_delete BEFORE DELETE ON runtime_policy_audit
BEGIN SELECT RAISE(ABORT, 'runtime policy audit is immutable'); END;

CREATE TRIGGER runtime_policy_audit_no_update BEFORE UPDATE ON runtime_policy_audit
BEGIN SELECT RAISE(ABORT, 'runtime policy audit is immutable'); END;

CREATE TRIGGER runtime_policy_version_no_delete BEFORE DELETE ON runtime_policy_version
BEGIN SELECT RAISE(ABORT, 'runtime policy versions are immutable'); END;

CREATE TRIGGER runtime_policy_version_no_update BEFORE UPDATE ON runtime_policy_version
BEGIN SELECT RAISE(ABORT, 'runtime policy versions are immutable'); END;

CREATE TRIGGER session_validation_policy_revision BEFORE UPDATE ON session_validation_policy
WHEN NEW.revision <= OLD.revision
BEGIN SELECT RAISE(ABORT, 'session validation policy revision must increase'); END;

CREATE TRIGGER token_issue_dpop_binding_immutable BEFORE UPDATE OF dpop_jkt ON token_issue
WHEN NEW.dpop_jkt IS NOT OLD.dpop_jkt
BEGIN SELECT RAISE(ABORT, 'token DPoP binding is immutable'); END;

CREATE TRIGGER vault_claim_disclosure_audit_no_delete BEFORE DELETE ON vault_claim_disclosure_audit
BEGIN SELECT RAISE(ABORT, 'claim disclosure audit is immutable'); END;

CREATE TRIGGER vault_claim_disclosure_audit_no_update BEFORE UPDATE ON vault_claim_disclosure_audit
BEGIN SELECT RAISE(ABORT, 'claim disclosure audit is immutable'); END;

CREATE TRIGGER vault_claim_release_account_stop_revoke AFTER UPDATE OF active,epoch ON account_security
WHEN NEW.active!=OLD.active OR NEW.epoch!=OLD.epoch
BEGIN
  UPDATE vault_claim_release SET status='revoked',version=version+1,
    updated_at=CAST(strftime('%s','now') AS INTEGER)
  WHERE account_id=NEW.account_id AND status='active';
END;

CREATE TRIGGER vault_claim_release_audit_no_delete BEFORE DELETE ON vault_claim_release_audit
BEGIN SELECT RAISE(ABORT, 'claim release audit is immutable'); END;

CREATE TRIGGER vault_claim_release_audit_no_update BEFORE UPDATE ON vault_claim_release_audit
BEGIN SELECT RAISE(ABORT, 'claim release audit is immutable'); END;

CREATE TRIGGER vault_claim_release_client_change_revoke AFTER UPDATE ON client
BEGIN
  UPDATE vault_claim_release SET status='revoked',version=version+1,
    updated_at=CAST(strftime('%s','now') AS INTEGER)
  WHERE client_id=NEW.client_id AND status='active';
END;

CREATE TRIGGER vault_claim_release_connection_change_revoke AFTER UPDATE ON app_connection
BEGIN
  UPDATE vault_claim_release SET status='revoked',version=version+1,
    updated_at=CAST(strftime('%s','now') AS INTEGER)
  WHERE account_id=NEW.account_id AND client_id=NEW.client_id AND status='active';
END;

CREATE TRIGGER vault_claim_release_policy_change_revoke AFTER UPDATE ON vault_claim_release_policy
BEGIN
  UPDATE vault_claim_release SET status='revoked',version=version+1,
    updated_at=CAST(strftime('%s','now') AS INTEGER)
  WHERE status='active';
END;

CREATE TRIGGER vault_claim_release_policy_revision BEFORE UPDATE ON vault_claim_release_policy
WHEN NEW.revision != OLD.revision + 1
BEGIN SELECT RAISE(ABORT, 'claim release policy revision must increase'); END;

CREATE TRIGGER vault_claim_release_record_grant_change AFTER UPDATE ON vault_record_grant
BEGIN UPDATE vault_claim_release SET status='revoked',version=version+1,updated_at=NEW.updated_at
 WHERE account_id=NEW.account_id AND source_storage_version=2 AND source_vault_id=NEW.vault_id
 AND source_collection_id=NEW.collection_id AND source_record_id=NEW.record_id AND status='active'; END;

CREATE TRIGGER vault_claim_release_record_insert BEFORE INSERT ON vault_claim_release
WHEN NEW.status='active' AND NEW.source_storage_version=2 AND NOT EXISTS (SELECT 1 FROM vault_record_grant g
 JOIN vault_record_recipient_envelope e ON e.envelope_id=g.envelope_id
 JOIN vault_owner_record_head h ON h.account_id=g.account_id AND h.vault_id=g.vault_id
  AND h.collection_id=g.collection_id AND h.record_id=g.record_id
 JOIN vault_owner_key_head root ON root.account_id=g.account_id AND root.vault_id=g.vault_id
 JOIN account_security a ON a.account_id=g.account_id
 JOIN vault_recipient_key k ON k.key_id=e.recipient_key_id
 JOIN vault_record_share_policy sp ON sp.id=1
 JOIN vault_claim_release_policy rp ON rp.id=1
 JOIN client c ON c.client_id=NEW.client_id
 JOIN app_connection ac ON ac.account_id=g.account_id AND ac.client_id=NEW.client_id
 WHERE g.account_id=NEW.account_id AND g.origin=NEW.source_origin AND g.vault_id=NEW.source_vault_id
 AND g.collection_id=NEW.source_collection_id AND g.record_id=NEW.source_record_id AND g.kind=NEW.source_kind
 AND g.record_revision=NEW.attribute_revision AND g.ciphertext_sha256=NEW.source_ciphertext_sha256
 AND g.key_generation=NEW.source_key_generation AND g.owner_key_revision=NEW.source_owner_key_revision
 AND g.recipient_service='userinfo' AND g.purpose='oidc.userinfo.name'
 AND g.status='active' AND g.version=NEW.system_grant_version AND g.expires_at>=NEW.expires_at
 AND h.deleted=0 AND h.kind=g.kind AND h.revision=g.record_revision AND h.ciphertext_sha256=g.ciphertext_sha256
 AND h.key_generation=g.key_generation AND h.format_version=2
 AND root.origin=g.origin AND root.key_generation=g.key_generation AND root.revision=g.owner_key_revision
 AND root.format_version=2 AND root.suite='PRF-HKDF-SHA256-AES256GCM-v2' AND a.active=1
 AND k.service_id='userinfo' AND k.state='active' AND k.generation=e.recipient_generation AND k.revision=e.directory_revision
 AND sp.enabled=1 AND sp.revision=e.policy_revision AND rp.enabled=1
 AND c.active=1 AND c.auth_method='private_key_jwt' AND c.revision=NEW.client_revision
 AND ac.active=1 AND ac.grant_version=NEW.connection_grant_version
 AND NEW.expires_at>unixepoch() AND NEW.expires_at<=unixepoch()+rp.ttl_seconds)
BEGIN SELECT RAISE(ABORT,'record claim release preconditions failed'); END;

CREATE TRIGGER vault_claim_release_record_update BEFORE UPDATE ON vault_claim_release
WHEN NEW.status='active' AND NEW.source_storage_version=2 AND NOT EXISTS (SELECT 1 FROM vault_record_grant g
 JOIN vault_record_recipient_envelope e ON e.envelope_id=g.envelope_id
 JOIN vault_owner_record_head h ON h.account_id=g.account_id AND h.vault_id=g.vault_id
  AND h.collection_id=g.collection_id AND h.record_id=g.record_id
 JOIN vault_owner_key_head root ON root.account_id=g.account_id AND root.vault_id=g.vault_id
 JOIN account_security a ON a.account_id=g.account_id
 JOIN vault_recipient_key k ON k.key_id=e.recipient_key_id
 JOIN vault_record_share_policy sp ON sp.id=1
 JOIN vault_claim_release_policy rp ON rp.id=1
 JOIN client c ON c.client_id=NEW.client_id
 JOIN app_connection ac ON ac.account_id=g.account_id AND ac.client_id=NEW.client_id
 WHERE g.account_id=NEW.account_id AND g.origin=NEW.source_origin AND g.vault_id=NEW.source_vault_id
 AND g.collection_id=NEW.source_collection_id AND g.record_id=NEW.source_record_id AND g.kind=NEW.source_kind
 AND g.record_revision=NEW.attribute_revision AND g.ciphertext_sha256=NEW.source_ciphertext_sha256
 AND g.key_generation=NEW.source_key_generation AND g.owner_key_revision=NEW.source_owner_key_revision
 AND g.recipient_service='userinfo' AND g.purpose='oidc.userinfo.name'
 AND g.status='active' AND g.version=NEW.system_grant_version AND g.expires_at>=NEW.expires_at
 AND h.deleted=0 AND h.kind=g.kind AND h.revision=g.record_revision AND h.ciphertext_sha256=g.ciphertext_sha256
 AND h.key_generation=g.key_generation AND h.format_version=2
 AND root.origin=g.origin AND root.key_generation=g.key_generation AND root.revision=g.owner_key_revision
 AND root.format_version=2 AND root.suite='PRF-HKDF-SHA256-AES256GCM-v2' AND a.active=1
 AND k.service_id='userinfo' AND k.state='active' AND k.generation=e.recipient_generation AND k.revision=e.directory_revision
 AND sp.enabled=1 AND sp.revision=e.policy_revision AND rp.enabled=1
 AND c.active=1 AND c.auth_method='private_key_jwt' AND c.revision=NEW.client_revision
 AND ac.active=1 AND ac.grant_version=NEW.connection_grant_version
 AND NEW.expires_at>unixepoch() AND NEW.expires_at<=unixepoch()+rp.ttl_seconds)
BEGIN SELECT RAISE(ABORT,'record claim release preconditions failed'); END;

CREATE TRIGGER vault_claim_release_source_insert BEFORE INSERT ON vault_claim_release
WHEN COALESCE(((NEW.source_storage_version=1 AND NEW.source_origin IS NULL AND NEW.source_vault_id IS NULL
 AND NEW.source_collection_id IS NULL AND NEW.source_record_id IS NULL AND NEW.source_kind IS NULL
 AND NEW.source_ciphertext_sha256 IS NULL AND NEW.source_key_generation IS NULL AND NEW.source_owner_key_revision IS NULL)
 OR (NEW.source_storage_version=2 AND NEW.source_origin IS NOT NULL AND NEW.source_vault_id IS NOT NULL
 AND NEW.source_collection_id='personal' AND NEW.source_record_id='name' AND NEW.source_kind='name'
 AND length(NEW.source_ciphertext_sha256)=43 AND NEW.source_key_generation BETWEEN 1 AND 9007199254740991
 AND NEW.source_owner_key_revision BETWEEN 1 AND 9007199254740991)),0)=0
BEGIN SELECT RAISE(ABORT,'invalid claim source'); END;

CREATE TRIGGER vault_claim_release_source_update BEFORE UPDATE ON vault_claim_release
WHEN COALESCE(((NEW.source_storage_version=1 AND NEW.source_origin IS NULL AND NEW.source_vault_id IS NULL
 AND NEW.source_collection_id IS NULL AND NEW.source_record_id IS NULL AND NEW.source_kind IS NULL
 AND NEW.source_ciphertext_sha256 IS NULL AND NEW.source_key_generation IS NULL AND NEW.source_owner_key_revision IS NULL)
 OR (NEW.source_storage_version=2 AND NEW.source_origin IS NOT NULL AND NEW.source_vault_id IS NOT NULL
 AND NEW.source_collection_id='personal' AND NEW.source_record_id='name' AND NEW.source_kind='name'
 AND length(NEW.source_ciphertext_sha256)=43 AND NEW.source_key_generation BETWEEN 1 AND 9007199254740991
 AND NEW.source_owner_key_revision BETWEEN 1 AND 9007199254740991)),0)=0
BEGIN SELECT RAISE(ABORT,'invalid claim source'); END;

CREATE TRIGGER vault_claim_release_version BEFORE UPDATE ON vault_claim_release
WHEN NEW.version != OLD.version + 1
BEGIN SELECT RAISE(ABORT, 'claim release version must increase'); END;

CREATE TRIGGER vault_gc_record_head_delete AFTER DELETE ON vault_owner_record_head
BEGIN
  INSERT OR IGNORE INTO vault_gc_candidate(object_key,eligible_at)
    SELECT OLD.object_key,unixepoch()+86400 WHERE OLD.object_key IS NOT NULL;
END;

CREATE TRIGGER vault_gc_record_head_insert AFTER INSERT ON vault_owner_record_head
BEGIN
  DELETE FROM vault_gc_candidate WHERE object_key=NEW.object_key AND state='pending';
END;

CREATE TRIGGER vault_gc_record_head_insert_guard BEFORE INSERT ON vault_owner_record_head
WHEN EXISTS(SELECT 1 FROM vault_gc_candidate WHERE object_key=NEW.object_key AND state='deleting')
BEGIN SELECT RAISE(ABORT,'vault_object_retired'); END;

CREATE TRIGGER vault_gc_record_head_update AFTER UPDATE OF object_key ON vault_owner_record_head
BEGIN
  INSERT OR IGNORE INTO vault_gc_candidate(object_key,eligible_at)
    SELECT OLD.object_key,unixepoch()+86400
    WHERE OLD.object_key IS NOT NULL AND OLD.object_key IS NOT NEW.object_key;
  DELETE FROM vault_gc_candidate WHERE object_key=NEW.object_key AND state='pending';
END;

CREATE TRIGGER vault_gc_record_head_update_guard BEFORE UPDATE OF object_key ON vault_owner_record_head
WHEN EXISTS(SELECT 1 FROM vault_gc_candidate WHERE object_key=NEW.object_key AND state='deleting')
BEGIN SELECT RAISE(ABORT,'vault_object_retired'); END;

CREATE TRIGGER vault_recipient_key_immutable BEFORE UPDATE ON vault_recipient_key
WHEN NEW.key_id != OLD.key_id OR NEW.service_id != OLD.service_id
  OR NEW.algorithm != OLD.algorithm OR NEW.public_key != OLD.public_key
  OR NEW.secret_ref != OLD.secret_ref OR NEW.generation != OLD.generation
  OR NEW.created_at != OLD.created_at
  OR (OLD.activated_at IS NOT NULL AND NEW.activated_at IS NOT OLD.activated_at)
  OR (OLD.retired_at IS NOT NULL AND NEW.retired_at IS NOT OLD.retired_at)
BEGIN SELECT RAISE(ABORT, 'vault recipient key identity is immutable'); END;

CREATE TRIGGER vault_recipient_key_insert BEFORE INSERT ON vault_recipient_key
WHEN NEW.state != 'staged' OR NEW.revision != 1
  OR NEW.activated_at IS NOT NULL OR NEW.retired_at IS NOT NULL
BEGIN SELECT RAISE(ABORT, 'vault recipient key must start staged'); END;

CREATE TRIGGER vault_recipient_key_no_delete BEFORE DELETE ON vault_recipient_key
BEGIN SELECT RAISE(ABORT, 'vault recipient key history cannot be deleted'); END;

CREATE TRIGGER vault_recipient_key_transition BEFORE UPDATE ON vault_recipient_key
WHEN NEW.revision != OLD.revision + 1
  OR NOT ((OLD.state = 'staged' AND NEW.state IN ('active', 'disabled'))
       OR (OLD.state = 'active' AND NEW.state IN ('decrypt_only', 'disabled'))
       OR (OLD.state = 'decrypt_only' AND NEW.state = 'disabled'))
  OR (OLD.state = 'staged' AND NEW.activated_at IS NOT NULL AND NEW.activated_at < OLD.created_at)
  OR (NEW.state IN ('decrypt_only', 'disabled') AND NEW.retired_at IS NOT NULL
      AND NEW.retired_at < COALESCE(NEW.activated_at, OLD.created_at))
BEGIN SELECT RAISE(ABORT, 'invalid vault recipient key transition'); END;

CREATE TRIGGER vault_record_envelope_no_delete BEFORE DELETE ON vault_record_recipient_envelope
BEGIN SELECT RAISE(ABORT,'record recipient envelope is immutable'); END;

CREATE TRIGGER vault_record_envelope_no_update BEFORE UPDATE ON vault_record_recipient_envelope
BEGIN SELECT RAISE(ABORT,'record recipient envelope is immutable'); END;

CREATE TRIGGER vault_record_grant_active_insert BEFORE INSERT ON vault_record_grant
WHEN NEW.status='active' AND NOT EXISTS (SELECT 1 FROM vault_record_recipient_envelope e
 JOIN vault_owner_record_head h ON h.account_id=e.account_id AND h.vault_id=e.vault_id
  AND h.collection_id=e.collection_id AND h.record_id=e.record_id
 JOIN vault_owner_key_head root ON root.account_id=e.account_id AND root.vault_id=e.vault_id
 JOIN account_security a ON a.account_id=e.account_id
 JOIN vault_recipient_key k ON k.key_id=e.recipient_key_id
 JOIN vault_record_share_policy p ON p.id=1
 WHERE e.envelope_id=NEW.envelope_id AND e.account_id=NEW.account_id
 AND e.origin=NEW.origin AND e.vault_id=NEW.vault_id AND e.collection_id=NEW.collection_id
 AND e.record_id=NEW.record_id AND e.kind=NEW.kind AND e.record_revision=NEW.record_revision
 AND e.ciphertext_sha256=NEW.ciphertext_sha256 AND e.key_generation=NEW.key_generation
 AND e.owner_key_revision=NEW.owner_key_revision AND e.recipient_service=NEW.recipient_service AND e.purpose=NEW.purpose
 AND h.deleted=0 AND h.kind=e.kind AND h.revision=e.record_revision AND h.ciphertext_sha256=e.ciphertext_sha256
 AND h.key_generation=e.key_generation AND h.format_version=2
 AND root.origin=e.origin AND root.key_generation=e.key_generation AND root.revision=e.owner_key_revision
 AND root.format_version=2 AND root.suite='PRF-HKDF-SHA256-AES256GCM-v2' AND a.active=1
 AND k.service_id=e.recipient_service AND k.algorithm='ML-KEM-768' AND k.state='active'
 AND k.generation=e.recipient_generation AND k.revision=e.directory_revision
 AND p.enabled=1 AND p.revision=e.policy_revision
 AND NEW.expires_at>unixepoch() AND NEW.expires_at<=unixepoch()+p.grant_ttl_seconds)
BEGIN SELECT RAISE(ABORT,'record grant preconditions failed'); END;

CREATE TRIGGER vault_record_grant_active_update BEFORE UPDATE ON vault_record_grant
WHEN NEW.status='active' AND NOT EXISTS (SELECT 1 FROM vault_record_recipient_envelope e
 JOIN vault_owner_record_head h ON h.account_id=e.account_id AND h.vault_id=e.vault_id
  AND h.collection_id=e.collection_id AND h.record_id=e.record_id
 JOIN vault_owner_key_head root ON root.account_id=e.account_id AND root.vault_id=e.vault_id
 JOIN account_security a ON a.account_id=e.account_id
 JOIN vault_recipient_key k ON k.key_id=e.recipient_key_id
 JOIN vault_record_share_policy p ON p.id=1
 WHERE e.envelope_id=NEW.envelope_id AND e.account_id=NEW.account_id
 AND e.origin=NEW.origin AND e.vault_id=NEW.vault_id AND e.collection_id=NEW.collection_id
 AND e.record_id=NEW.record_id AND e.kind=NEW.kind AND e.record_revision=NEW.record_revision
 AND e.ciphertext_sha256=NEW.ciphertext_sha256 AND e.key_generation=NEW.key_generation
 AND e.owner_key_revision=NEW.owner_key_revision AND e.recipient_service=NEW.recipient_service AND e.purpose=NEW.purpose
 AND h.deleted=0 AND h.kind=e.kind AND h.revision=e.record_revision AND h.ciphertext_sha256=e.ciphertext_sha256
 AND h.key_generation=e.key_generation AND h.format_version=2
 AND root.origin=e.origin AND root.key_generation=e.key_generation AND root.revision=e.owner_key_revision
 AND root.format_version=2 AND root.suite='PRF-HKDF-SHA256-AES256GCM-v2' AND a.active=1
 AND k.service_id=e.recipient_service AND k.algorithm='ML-KEM-768' AND k.state='active'
 AND k.generation=e.recipient_generation AND k.revision=e.directory_revision
 AND p.enabled=1 AND p.revision=e.policy_revision
 AND NEW.expires_at>unixepoch() AND NEW.expires_at<=unixepoch()+p.grant_ttl_seconds)
BEGIN SELECT RAISE(ABORT,'record grant preconditions failed'); END;

CREATE TRIGGER vault_record_grant_version BEFORE UPDATE ON vault_record_grant
WHEN NEW.version != OLD.version+1
BEGIN SELECT RAISE(ABORT,'record grant version must increase'); END;

CREATE TRIGGER vault_record_share_account_change AFTER UPDATE ON account_security WHEN NEW.active!=OLD.active OR NEW.epoch!=OLD.epoch
BEGIN UPDATE vault_record_grant SET status='revoked',version=version+1,updated_at=unixepoch()
 WHERE status='active' AND account_id=NEW.account_id; END;

CREATE TRIGGER vault_record_share_audit_no_delete BEFORE DELETE ON vault_record_share_audit
BEGIN SELECT RAISE(ABORT,'record share audit is immutable'); END;

CREATE TRIGGER vault_record_share_audit_no_update BEFORE UPDATE ON vault_record_share_audit
BEGIN SELECT RAISE(ABORT,'record share audit is immutable'); END;

CREATE TRIGGER vault_record_share_head_change AFTER UPDATE ON vault_owner_record_head
BEGIN UPDATE vault_record_grant SET status='revoked',version=version+1,updated_at=unixepoch()
 WHERE status='active' AND account_id=NEW.account_id AND vault_id=NEW.vault_id AND collection_id=NEW.collection_id AND record_id=NEW.record_id; END;

CREATE TRIGGER vault_record_share_policy_change AFTER UPDATE ON vault_record_share_policy
BEGIN UPDATE vault_record_grant SET status='revoked',version=version+1,updated_at=unixepoch()
 WHERE status='active' AND 1; END;

CREATE TRIGGER vault_record_share_policy_revision BEFORE UPDATE ON vault_record_share_policy
WHEN NEW.revision != OLD.revision+1
BEGIN SELECT RAISE(ABORT,'record share policy revision must increase'); END;

CREATE TRIGGER vault_record_share_recipient_change AFTER UPDATE ON vault_recipient_key
BEGIN UPDATE vault_record_grant SET status='revoked',version=version+1,updated_at=unixepoch()
 WHERE status='active' AND envelope_id IN (SELECT envelope_id FROM vault_record_recipient_envelope WHERE recipient_key_id=NEW.key_id); END;

CREATE TRIGGER vault_record_share_root_change AFTER UPDATE ON vault_owner_key_head
BEGIN UPDATE vault_record_grant SET status='revoked',version=version+1,updated_at=unixepoch()
 WHERE status='active' AND account_id=NEW.account_id; END;

CREATE TRIGGER web_login_transaction_capacity BEFORE INSERT ON web_login_transaction
WHEN (SELECT count(*) FROM web_login_transaction WHERE consumed=0 AND expires_at>unixepoch()) >= (SELECT pending_total FROM auth_resource_policy WHERE id=1)
 OR (SELECT count(*) FROM web_login_transaction WHERE browser_hash=NEW.browser_hash AND consumed=0 AND expires_at>unixepoch()) >= (SELECT pending_per_browser FROM auth_resource_policy WHERE id=1)
BEGIN SELECT RAISE(ABORT,'auth_capacity_exceeded'); END;

-- Required initial singleton policy and enrollment state. Public registrations
-- and runtime policy versions are installed by the reviewed initialization workflow.
INSERT INTO client(client_id,revision,active,auth_method,allow_missing_pkce,sector_identifier)
  VALUES('mikaki-internal-enrollment',1,1,'private_key_jwt',0,'mikaki.internal');
INSERT INTO bootstrap_state(id,closed) VALUES(1,0);
INSERT INTO enrollment_policy(id,bootstrap_ttl_seconds,invite_ttl_seconds,management_ttl_seconds,registration_ttl_seconds,revision)
  VALUES(1,900,86400,300,300,1);
INSERT INTO session_validation_policy(id,lease_ttl_seconds,app_idle_timeout_seconds,revision)
  VALUES(1,300,604800,1);
INSERT INTO vault_claim_release_policy(id,enabled,ttl_seconds,revision) VALUES(1,0,86400,1);
INSERT INTO vault_record_share_policy(id,enabled,grant_ttl_seconds,revision) VALUES(1,0,604800,1);
INSERT INTO auth_resource_policy VALUES(1,120,600,5,100,1000);
INSERT INTO vault_owner_record_gc_cursor(id,cursor) VALUES(1,NULL);
