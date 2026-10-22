# Passport evidence verification interface

`mikaki_identity::passport` is the shared, platform-independent DG1/SOD verifier.
The Android Wallet uses the same implementation that a server can call. It needs
neither NFC transport, BAC/DES, Tauri nor a WebView. Verification time and CRL
policy are supplied by the calling application, outside the evidence payload.

This verifier underpins the separately gated first-party `passport_dg1` issuance
path described below. Existing linked-document issuers continue to reject
`DocumentType::Passport`. The DG1 profile is Mikaki-issued and does not represent a
government DTC, current travel validity, face match or live-chip authentication.

## Input and verification

`Evidence::from_bytes(dg1, sod)` accepts the original 93-byte TD3 EF.DG1 and an
EF.SOD of 1–8192 bytes. `Evidence` can also be serialized/deserialized as exactly
two fields, `dg1` and `sod`, containing canonical unpadded Base64url. Extra or
duplicate fields, byte arrays, padded/alternate encodings and oversized values
are rejected. Owned evidence and temporary encoding buffers are zeroized on drop.
Worker intake bounds the complete request to 16 KiB before JSON decoding; the
shared decoder independently enforces the evidence bounds.

There is no input field for local previews, user-entered full years, cached reports,
claimed trust state, issuer roots or communication/holder keys. `Policy::default()`
uses the pinned Japanese roots and bundled complete CRL. `Policy::from_json()`
retains the existing build-time CRL configuration format: bounded, canonical padded
standard Base64 DER CRLs in a JSON array. Neither method enrolls new roots.

```rust
use mikaki_identity::passport::{Evidence, Policy};

fn verify_for_issuer(
    dg1: Vec<u8>, sod: Vec<u8>, trusted_server_time: u64,
) -> Result<(), Box<dyn std::error::Error>> {
    let evidence = Evidence::from_bytes(dg1, sod)?;
    let policy = Policy::default();
    let diagnostic = evidence.inspect(&policy, trusted_server_time);
    let verified = evidence.verify(&policy, trusted_server_time)?;
    let claims = verified.claims();
    let recheck_before = verified.evidence_valid_until();
    Ok(())
}
```

`inspect` returns a diagnostic report for UI. `verify` requires all of the following
together: supported, valid TD3 MRZ structure/calendar/check digits; matching DG1
hash and CMS signature; the MRZ issuer's pinned CSCA chain; currently valid DSC/CSCA;
and a fresh authenticated complete CRL without DSC/CSCA revocation. Missing, stale,
unsupported or invalid CRLs never become a successful `VerifiedDg1`.

`VerifiedDg1` has private fields, read-only accessors and no deserialization or
report-to-result conversion. Public callers must reverify original evidence; a
client's serialized diagnostic result cannot manufacture verification authority.
Synthetic roots used by independent OpenSSL tests are not configurable in the
production policy. Source/pins/CRL refresh instructions are in
[the shared trust directory](../crates/identity/src/passport/trust/README.md).

## Signed claims and unresolved dates

The read-only projection contains:

| Field | Meaning |
| --- | --- |
| `name_mrz` | Uppercase MRZ transliteration with fillers rendered as spaces |
| `issuing_state` | Signed three-character issuing authority code |
| `nationality` | Signed three-character nationality code |
| `birth_date_mrz` | Exact six digits `YYMMDD` |
| `expiry_date_mrz` | Exact six digits `YYMMDD` |
| `sex_mrz` | Exact MRZ `M`, `F` or `<` value |

There is no automatic claim for a full birth date, full expiry year, age predicate,
address, portrait, document number, personal number or complete MRZ. The signed
two-digit date representation is specified by
[ICAO Doc 9303 Part 3, section 4.8](https://www.icao.int/sites/default/files/publications/DocSeries/9303_p3_cons_en.pdf).
The local reader's user-entered century is useful for BAC access and display; it
does not add a signed century to DG1. An independently authenticated full date
would need separate evidence, such as supported and hash-verified DG11 data; DG11
is optional and is not read by this implementation. This subset requires complete
calendar dates, traditional TD3 document numbers and the signature profiles
described in [the Wallet scope](identity-wallet.md#dg1sod-consistency).

`evidence_valid_until` is a certificate/CRL freshness upper bound. It is **not**
the physical passport's expiry date. The DG1 credential explicitly records
`document_validity_verified: false`, preserves unresolved years, and never reuses
that deadline as travel validity. DG1 authenticity does not establish live-chip possession, a face match,
current travel entitlement or control of the future credential's holder key.

## Connection to issuance and presentation

The raw evidence envelope contains the full MRZ, including identifiers, even though
the result projection omits them. It is not a selective-disclosure credential and
is never sent automatically when reading, saving or opening a Wallet card. No new
automatic evidence transfer occurs through this shared interface. The explicit
first-party issuance action below is the only new raw-evidence network path.

The separate `mikaki_identity::passport::credential` module defines configuration
`passport_dg1`, VCT `${issuer}/types/passport-dg1` and the six-field SD-JWT profile.
`issue` accepts only a `VerifiedDg1` checked at the supplied issuance time, a distinct
holder public key and an explicit deadline; signing is bounded to five minutes,
all evidence deadlines and optional issuer certificate trust. A diagnostic report
or deserialized projection cannot enter this API. The receipt verifier enforces
this VCT's field/metadata allowlist and never upgrades it to linked-document claims.

Native review loads only current-owner saved evidence and creates a dedicated
Wallet linkage key. Confirmation uploads original evidence to
`/identity/passport/intake`. In HAIP mode the native client then authenticates its
Wallet instance and sends PAR to the existing issuer with `scope=passport_dg1`,
S256 PKCE, DPoP and the temporary transaction ID in standard `issuer_state`.
The PAR sender key must equal the reviewed linkage key. The browser owner approves
six attributes, account and authenticated Wallet at the existing authorization
endpoint; PAR consumption and the code response are bound to owner/session/epoch,
client attestation, CSRF, redirect, Wallet state and issuer.

The existing authenticated token exchange verifies PKCE and DPoP. The encrypted
Credential request resends original `passport_evidence`, a nonce and an attested
holder proof. The fresh holder key is distinct from the DPoP linkage key. Both
`jwt` with `key_attestation` and direct `attestation` proof forms are supported by
the issuer. It rechecks the exact original evidence hash, projection, current
pinned trust/policy and owner epoch before signing, with validity clipped by the
key-attestation lifetime as well. Atomic completion consumes the nonce and scrubs
projected attributes and grant/evidence references. No new issuer is introduced;
HAIP mode closes the prototype's poll/direct-approval/pre-authorized flow.

The server's review deadline is at most ten minutes, followed by bounded expired-row
collection. DG1/SOD are never stored server-side. The native issued receipt is
memory-only, owner-bound and disappears on expiry, owner change or process exit.
Reading/saving and receipt/presentation consent remain separate operations. The
feature is disabled unless `IDENTITY_PASSPORT_ENABLED=true` alongside the identity
feature. HAIP additionally uses the existing Wallet/attestation configuration. Migration, configuration and UI details
are in [the Wallet implementation](identity-wallet.md#passport-dg1-credential-issuance).

The resulting SD-JWT participates in the existing verified-receipt OID4VP/DCQL
inventory. Selection checks its actual VCT before choosing disclosures and binds
presentation to its holder key. No passport mdoc, nearby presentation or generic
Multipaz reception of the custom first-party evidence extension is qualified.

Positive cryptographic/profile tests use independently generated OpenSSL CMS,
CSCA and CRL fixtures through a test-only synthetic trust path. Production policy
cannot enroll these roots. Workerd tests use the real pinned production policy to
reject synthetic evidence, and privileged test-database seeds separately exercise
owner consent, one-use grants and nonce/scrub transactions. They do not demonstrate
successful Japanese-passport issuance. Real-passport intake, installed Android
round-trip, external Wallet interoperability and production activation remain
separate qualification steps.

`Policy::valid_until(now)` is an operational readiness check over the independently
pinned anchors and authenticated complete CRLs. It accepts no passport, grants no
identity authority and cannot construct `VerifiedDg1`. Metadata exposes only its
fingerprint/deadline; readiness fails for missing/stale CRLs, missing issuer key or
missing passport schema. This does not change the original-evidence verification
required for every credential.
