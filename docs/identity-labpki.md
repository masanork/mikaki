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
