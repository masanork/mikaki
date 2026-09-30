# MDS validation and update boundary

Mikaki's core validates a signed FIDO Metadata Service BLOB offline; product retrieval, persistence, and authenticator policy application are separate. The referenced format is the [FIDO MDS 3.1.1 Proposed Standard](https://fidoalliance.org/specs/mds/fido-metadata-service-v3.1.1-ps-20260105.html). Entries identify authenticators by AAGUID or attestation certificate key identifier and may contain status, effective date, firmware version, and affected certificate.

`verify_mds` validates signature, signer chain, and supplied CRL, then returns required JWT `iat`, BLOB number, optional `nextUpdate`, and entries. U2F key identifiers are stored as 40 lowercase hex characters. Each status report preserves its signed fields, including `effectiveDate`, `authenticatorVersion`, `batchCertificate`, `certificate`, `url`, and unknown future fields. Firmware version and `timeOfLastStatusChange` are retained. Unknown status strings are retained, not treated as parse failures. Because `nextUpdate` is being deprecated, it may be absent and is not used as the freshness gate. The core does not fetch `x5u` signer certificates and currently rejects that form; it processes supplied `x5c`.

The current conservative `allowed` policy sets an entire entry false if any report contains `USER_VERIFICATION_BYPASS`, `ATTESTATION_KEY_COMPROMISE`, `USER_KEY_REMOTE_COMPROMISE`, `USER_KEY_PHYSICAL_COMPROMISE`, or `REVOKED`. It does so even when a report targets only one firmware version or certificate, because the core does not yet evaluate firmware certificate extensions at attestation time. Retaining detailed fields is not firmware-specific enforcement. RP policy ultimately determines status acceptance; see the [MDS status rules](https://fidoalliance.org/specs/mds/fido-metadata-service-v3.1.1-ps-20260105.html#statusreport-dictionary).

## Node operation adapter (2026-09-29)

[local/mds.ts](../local/mds.ts) implements HTTPS retrieval and durable SQLite snapshots. [scripts/mds-refresh.ts](../scripts/mds-refresh.ts) provides `refresh`, `status`, and an hourly `watch`. Trust is configured out of band: the URL, explicit profile, pinned anchor SPKI, allowed download hosts, and maximum age are fingerprinted into the database. Changing that channel requires a separate database; existing state cannot silently become a different trust domain or compatibility profile.

```sh
node scripts/mds-refresh.ts refresh /path/to/mds-config.json target/mds.sqlite
node scripts/mds-refresh.ts status /path/to/mds-config.json target/mds.sqlite
node scripts/mds-refresh.ts watch /path/to/mds-config.json target/mds.sqlite
```

Configuration shape (supply a independently obtained root SPKI; this placeholder is deliberately unusable):

```json
{
  "url": "https://mds3.fidoalliance.org/",
  "profile": "mds3.1.1",
  "anchor_spki": "REPLACE_WITH_BASE64URL_DER_PINNED_ROOT_SPKI",
  "allowed_hosts": ["mds3.fidoalliance.org"],
  "max_age_seconds": 604800
}
```

Add only independently approved CRL hosts with HTTPS endpoints; certificate hints do not expand the allow-list. HTTP-only CRL URLs are rejected. Redirects are checked individually (maximum three); a shared 20-second request deadline and 4 MiB BLOB / 1 MiB CRL streaming limits apply. At most twelve CRL hints are accepted. Neither JWT-supplied roots nor `x5u` are used for trust.

The writer verifies the entire candidate, takes `BEGIN IMMEDIATE`, and compares its signed serial with the stored high-water mark. A lower serial or changed JWT at the same serial is rejected. The identical BLOB can be reverified with refreshed CRLs without resetting its original retrieval time. Number, validated input, time, and all entries commit together with WAL and `synchronous=FULL`. Fetch or verification failure preserves the snapshot, records a bounded reason and attempt time, and makes the one-shot CLI exit nonzero. Watch emits status each hour for operator monitoring, including on failure; it does not install a background service or alert recipient.

`forRegistration(now)` revalidates certificate and CRL time and refuses missing/stale snapshots. Freshness is bounded by both first retrieval and signed `iat` (300-second future clock tolerance). Legacy `mds3.0` additionally requires signed `nextUpdate`; repeated retrieval cannot extend the same BLOB indefinitely. Maximum age is explicit, between one hour and 31 days. Existing passkey authentication and existing-credential reassessment are separate RP decisions.

Four [operation regressions](../local/conformance/mds-operation.test.ts) use independent signed ES256/RS256 BLOBs to check persistence/restart, two SQLite connections, rollback/equivocation, configuration isolation, atomic preservation after signature/transport failure, freshness/CRL expiry, and hostile download destinations. Reproduce after building browser-wasm:

```sh
node --test local/conformance/mds-operation.test.ts
```

The core now verifies ES256 and RS256 JWT signatures with algorithm/key binding. Native and Wasm share independent valid and mismatched-algorithm fixtures. No acceptance fallback was added.

## Product enablement boundary

1. Allow-list distribution and download hosts. Treat BLOB `x5u` and CRL URLs as untrusted input; do not add HTTP fetching to the core.
2. Validate the entire candidate and require a BLOB number greater than the stored high-water mark. Record `iat` and retrieval time. Define operational freshness/retry separately; do not require `nextUpdate`.
3. Atomically replace number, validity data, and all entries as one snapshot only after complete validation. Never publish partial entries or advance the number first.
4. On fetch/verification failure, preserve the last validated snapshot and record failure and snapshot age. Define how stale a snapshot can be for new registrations. Whether ordinary passkey authentication continues without MDS is a separate product policy.
5. Decide separately whether updated status changes existing credentials. Do not automatically delete a credential or session on MDS update. Reassessment would require stored registration attestation evidence and its metadata snapshot.

The FIDO [MDS changelog](https://fidoalliance.org/mds-changelog/) records an R3→R46 cross-certificate transition beginning 2026-08-31. The current six-certificate chain limit accommodates it; operators would need to add R46 to trust and migrate before the recorded 2029-03-18 expiry of the old R3 path.

Product MDS remains disabled. The Node adapter is ready for explicit operation, but is not wired into Workers/D1 or the product registration policy. Product enablement still needs an approved production trust/host configuration, a fresh accepted feed, deployment-specific scheduling/monitoring, and the RP's choice of freshness/status policy. The inspected public and test feeds still omit the 3.1.1-required header `iat`; the strict profile rejects them. Test compatibility is explicitly `mds3.0`, and is never inferred from content. Firmware/certificate-specific reassessment and automated alert delivery remain separate product work.
