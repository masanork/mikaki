-- Authorization-code binding is separate from the access token's DPoP key.
ALTER TABLE identity_wallet_grant ADD COLUMN authorization_dpop_jkt TEXT
  CHECK(authorization_dpop_jkt IS NULL OR length(authorization_dpop_jkt)=43);
