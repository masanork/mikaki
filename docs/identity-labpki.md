# LabPKI development trust for HAIP

The operator's `~/repo/ocspd` LabPKI can supply development trust for Mikaki.
Its existing RSA, P-384 and PQC suites and JPKI-style `clientAuth` leaves cannot be
used directly by Mikaki's P-256/SHA-256 HAIP validators. The dedicated LabPKI
`haip-init` / `haip-issue` commands create separate SD-JWT, Attester and mdoc
authorities without rotating the existing LabPKI suites.

This preparation is a PKI compatibility check. It does not activate HAIP, register
a verifier, establish government card trust or qualify an Android device.

## Prepare from an existing Identity signer

Build the updated LabPKI CLI in the ocspd checkout:

```sh
go build -o /private/tmp/labpki-haip ./cmd/labpki
```

From Mikaki, select the dedicated Identity private JWK file and two new, distinct
directories. The existing OP signing key is not a valid choice for this purpose.

```sh
node scripts/prepare-identity-labpki.ts \
  /private/tmp/labpki-haip \
  /path/to/dedicated-identity-issuer.jwk.json \
  local/generated/identity-labpki-development \
  /path/to/ocspd/local/haip/mikaki-development \
  http://localhost:8080

cargo run -p mikaki-identity --locked --example check_haip_pki -- \
  local/generated/identity-labpki-development/public-pki-bundle.json
```

The helper verifies private key permissions and matching P-256 public coordinates,
then signs an Issuer CSR through OpenSSL stdin. The private issuer key is never
written into the CA directory or passed on a command line. The same Issuer public
key gets separate SD-JWT and mdoc signing certificates. The script generates fresh
Attester and credential-request encryption keys, separate from the Issuer key.
Every preparation requires new directories and fresh CA authorities; it is not a
renewal command and must not be used to replace established runtime trust silently.

| Application output | Intended use |
| --- | --- |
| `public-pki-bundle.json` | Public-only input to the actual Rust PKI/configuration validators |
| `issuer-public-settings.json` | Credential signing chains, client/key Attester roots, proposed exact Wallet registration and required DPoP nonce mode; no enable flags |
| `MIKAKI_HAIP_WALLET.json` | Public trust configuration for a future Android build |
| `attester-signing.secret.json` | Proposed `IDENTITY_ATTESTER_SIGNING` secret; private signing JWK and certificate chain |
| `credential-encryption.secret.jwk.json` | Proposed dedicated `IDENTITY_CREDENTIAL_ENCRYPTION_JWK` secret |
| `issuer.csr`, `attester.csr` | Signed public requests; application private keys are not included |

Application and CA output directories use mode 0700; application secret JSON and
CA keys use mode 0600. Keep both sets out of Git and deployment artifacts. The
existing Identity signer remains in its original custody location.

The prepared registration uses client `mikaki-android-wallet`, exact callback
`https://app.mikaki.org/identity/issuance/callback`, and the native broker issuer
`https://auth.mikaki.org/identity/attester`. They are proposals in local files,
not registrations that have been deployed. The native profile currently requires
distinct SD-JWT and mdoc roots even if initially only SD-JWT is issued; those
credential roots are also separate from Attester trust.

## CRL and validation contract

Credential signing policies explicitly include seven-day complete CRL snapshots.
The helper issues and revokes an additional SD-JWT certificate for a negative
probe; it does not revoke either selected signing certificate. That probe shares
the Issuer public key, demonstrating that revocation applies to certificates,
not every certificate containing that public key.

`check_haip_pki` reads no private keys. It validates actual LabPKI-issued SD-JWT,
mdoc and Attester chains, checks public-key bindings, validates the native Wallet
configuration and agreement of Issuer/Wallet roots. It also requires rejection of
a revoked certificate, wrong CA, root included in x5c, wrong signing key, wrong
certificate purpose, expired Attester and expired credential CRL policy.

Refresh and reimport complete CRLs before their nextUpdate/freshness deadline.
Running `labpki crl` updates CA-side files only: the Issuer settings, public bundle
and compiled Wallet configuration must receive the new validated snapshots too.
Mikaki does not fetch OCSP or CRL URLs at runtime. Attester chain validation
currently does not apply a CRL policy; preparing an Attester CRL does not add
runtime revocation enforcement for those JWTs.

### Renew the selected snapshots without rotating trust

The [read-only expiry monitor](security-ci.md#identity-trust-expiry-monitoring)
checks the source-selected public snapshot every six hours and fails at or within
48 hours of a certificate/CRL freshness or recorded card-approval deadline. Run
`npm run check:identity-trust-freshness` locally before renewal and again after
import. Treat an alert as a request for reviewed maintenance; it does not extend
trust or establish that new bytes reached a running Issuer or installed Wallet.

Use the existing HAIP CA directory and its complete `registry.db`. First compare
each `haip-sd-jwt/root.pem` and `haip-mdoc/root.pem` with the corresponding pinned
`trust_anchors` in `crates/worker/config/identity-haip-labpki.public.json`. Preserve
the previous public CRLs for comparison and confirm that the registry still
contains the revoked SD-JWT probe. An absent registry or mismatched root is an
error; do not initialize a replacement CA to repair an expired CRL.

```sh
labpki crl -out /path/to/existing/haip-ca -algo haip-sd-jwt
labpki crl -out /path/to/existing/haip-ca -algo haip-mdoc
```

Verify each new `ca.crl` against its pinned root, its current validity and newer
CRL number, and retention of every previous revoked serial/date/reason. Import
its base64 DER into the matching `credential_certificates` and
`wallet_configuration.credential_trust` CRL arrays in the public bundle. Also
update `revoked_sd_jwt.revocation.crls` with the same SD-JWT snapshot. These five
arrays are the only bundle values that change: keep all certificates, keys,
anchors and `max_age_seconds: 604800` intact. Then synchronize only
`IDENTITY_CREDENTIAL_CERTIFICATES` and `IDENTITY_HAIP_POLICY_SHA256` in
`crates/worker/wrangler.production.jsonc` from `identityHaipSelection().vars`.
Re-export the updated bundle's `wallet_configuration` as the build-time
`MIKAKI_HAIP_WALLET` JSON. Installed Wallets need the normal rebuild and release
process to receive the new snapshots.

```sh
cargo run -p mikaki-identity --locked --example check_haip_pki -- \
  crates/worker/config/identity-haip-labpki.public.json
node --test scripts/identity-haip-profile.test.ts
```

Run these checks with the real current time. The validator must still reject the
revoked probe and expired CRLs. Submit the public changes through the normal
review, CI and promotion path; CA-side renewal alone does not update a running
Issuer or installed Wallet.

On 2026-10-22 JST, the selected snapshots were renewed with the same roots and
complete revocation registry. Both are valid from `2026-10-21T21:43:47Z` until
`2026-10-28T21:43:47Z`. Renewal preserved the revoked probe, all certificate/key
bindings and the seven-day freshness policy. This is public snapshot maintenance;
it does not establish deployment or physical-device issuance.

### Public snapshot renewal — 2026-10-30

The existing `mikaki-20261015` HAIP authorities and complete revocation registry
were used to renew the SD-JWT and mdoc CRLs. Their selected roots match the
previously pinned DER certificates. The new CRLs are valid from
`2026-10-30T09:38:47Z` until `2026-11-06T09:38:47Z`; CRL numbers increase, all
previous serial/date/reason records are retained, and the registry bytes are
unchanged. SD-JWT retains its one revoked probe; mdoc has no revoked entries.

Only the five CRL arrays were replaced in the public bundle. All certificates,
keys, anchors and seven-day freshness limits remain unchanged. The source
credential-certificate variable and derived HAIP policy digest were synchronized.
The actual Rust checker passes Wallet/Issuer binding and all seven negative
checks at the current time. This updates source snapshots, not an installed
Wallet or an active service.

The separate single-card operator approval expired on 2026-10-28. Its proposed
extension is awaiting explicit operator review under the
[existing renewal procedure](identity-test-deployment.md#proposed-single-card-trust-renewal--2026-10-22).
CRL renewal does not extend that approval or authorize provisioning a new card
trust secret.

## Next activation work

1. Select the public CA/CRL distribution URL and protect offline CA custody.
   LabPKI's added distribution routes require only public roots/CRLs; never deploy
   the HAIP CA private keys with the responder.
2. Provision the [Android verifier](../services/android-attestation-verifier/README.md)
   using the signed application's actual package/certificate/version and device
   policy, authenticated HTTPS ingress and the private Worker service binding.
   LabPKI attests the broker's signing authority; Android/Google roots validate
   hardware evidence independently.
3. Register the resulting verifier policy hash in `IDENTITY_ATTESTER_CLIENTS`.
   Select CA custody, secrets and the exact HAIP profile in the production
   deployment validator and CI, which currently permit the first-party age slice.
4. Compile the explicit public Wallet configuration and perform native enrollment,
   PAR/owner approval, token exchange and encrypted credential receipt. HAIP on the
   same Issuer disables its current pre-authorized token exchange; preserve that
   flow using a separate deployment if needed.

See the [native enrollment contract](identity-card-issuance.md#native-attester-enrollment-broker)
and [current activation profile](identity-test-deployment.md).

## Local checkpoint — 2026-10-15

In isolated ocspd and Mikaki worktrees, fresh development authorities issued
certificates for the existing dedicated Identity signer and a newly generated
Attester signer. All three certificate validations, native Wallet configuration
and seven negative checks passed using the actual Rust validators. The dedicated
Issuer thumbprint remained `aI1NQnj1WPnTUqYPXyQDj6ASntF1C8DMzfO-12bE7y4`.
Private roots, secret files and generated public bundles are local ignored files.
No Cloud Run/Worker deployment, CI secret provisioning, Android hardware
attestation or HAIP runtime activation was performed by this checkpoint.

## Server provisioning checkpoint — 2026-10-15

The follow-up deployment uses Cloud Run project `ocspd-poc-masanork`, region
`asia-northeast1`, service `mikaki-android-verifier`. The first qualified image is
`sha256:99446ad01e76588e519b5cced1723020e329d55440d04700a2e012f7dc110455`,
built from verifier source `15edd6b5ee4cccaf68e22a79f3f832e0e6b332e7`.
The runtime service account can read only the dedicated verifier token secret;
the container has no CA/Issuer/Attester private keys. Cloud Run IAM invocation
checking is disabled for this shared-token transport; the JVM authenticates both
`POST /verify` and `GET /readyz` before processing. Its policy is embedded in the
immutable image; changes require recomputing and registering the policy hash.

The selected app is `app.tossa.mikaki`, version code at least 1000, with signing
certificate SHA-256
`fc5138fe5c6e0555ad085e4d68daf9dbf67693631e72c941a17d17800deb0066`.
Initial device thresholds follow the existing example: Android 14, September 2026
OS/vendor/boot patches, TEE and locked Verified Boot. They are an operator test
policy pending physical-device confirmation, not a hardware qualification result.
The resulting verifier policy identifier is
`q3js6eUGLqFvJvrrdkWs8pzbeH0vUMSo0EzCGSh6GBo`.

The bridge production config pins the HTTPS `/verify` destination and policy/client
identity. Its authenticated `/readyz` transport independently checks the JVM's
current Google-status deadline. Platform logs/traces are enabled with query
redaction and invocation logs disabled; application errors contain only a fixed
availability event, never tokens, evidence, JWTs or account details.

The OP adds a separate, ready-token-protected `/identity/ready` endpoint. It checks
the source-selected certificate/key custody and the actual verifier dependency,
returning 204 when available and 503 when policy, trust or status does not match.
The base OP `/ready` remains independent. Main CI validates the public LabPKI
bundle with the actual Rust validators and permits only the exact selected HAIP
variables, secrets and service binding before promotion. Production smoke checks
authorization-code-only metadata, PAR, client/key attestation, DPoP, encryption,
age-only claims, dedicated public signing key and this protected readiness.

Private receipts and the signed release APK are retained in ignored local output;
their existence does not establish physical-device issuance. CRL snapshots still
need reimport before their seven-day freshness deadline, and the previously
approved card trust still expires at its original operator-selected deadline.
