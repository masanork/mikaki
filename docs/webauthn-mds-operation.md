# MDS validation and update boundary

Mikaki's core validates a signed FIDO Metadata Service BLOB offline; product retrieval, persistence, and authenticator policy application are separate. The referenced format is the [FIDO MDS 3.1.1 Proposed Standard](https://fidoalliance.org/specs/mds/fido-metadata-service-v3.1.1-ps-20260105.html). Entries identify authenticators by AAGUID or attestation certificate key identifier and may contain status, effective date, firmware version, and affected certificate.

`verify_mds` validates signature, signer chain, and supplied CRL, then returns required JWT `iat`, BLOB number, optional `nextUpdate`, and entries. U2F key identifiers are stored as 40 lowercase hex characters. Each status report preserves its signed fields, including `effectiveDate`, `authenticatorVersion`, `batchCertificate`, `certificate`, `url`, and unknown future fields. Firmware version and `timeOfLastStatusChange` are retained. Unknown status strings are retained, not treated as parse failures. Because `nextUpdate` is being deprecated, it may be absent and is not used as the freshness gate. The core does not fetch `x5u` signer certificates and currently rejects that form; it processes supplied `x5c`.

The current conservative `allowed` policy sets an entire entry false if any report contains `USER_VERIFICATION_BYPASS`, `ATTESTATION_KEY_COMPROMISE`, `USER_KEY_REMOTE_COMPROMISE`, `USER_KEY_PHYSICAL_COMPROMISE`, or `REVOKED`. It does so even when a report targets only one firmware version or certificate, because the core does not yet evaluate firmware certificate extensions at attestation time. Retaining detailed fields is not firmware-specific enforcement. RP policy ultimately determines status acceptance; see the [MDS status rules](https://fidoalliance.org/specs/mds/fido-metadata-service-v3.1.1-ps-20260105.html#statusreport-dictionary).

## Requirements for a future retrieval adapter

1. Allow-list distribution and download hosts. Treat BLOB `x5u` and CRL URLs as untrusted input; do not add HTTP fetching to the core.
2. Validate the entire candidate and require a BLOB number greater than the stored high-water mark. Record `iat` and retrieval time. Define operational freshness/retry separately; do not require `nextUpdate`.
3. Atomically replace number, validity data, and all entries as one snapshot only after complete validation. Never publish partial entries or advance the number first.
4. On fetch/verification failure, preserve the last validated snapshot and record failure and snapshot age. Define how stale a snapshot can be for new registrations. Whether ordinary passkey authentication continues without MDS is a separate product policy.
5. Decide separately whether updated status changes existing credentials. Do not automatically delete a credential or session on MDS update. Reassessment would require stored registration attestation evidence and its metadata snapshot.

The FIDO [MDS changelog](https://fidoalliance.org/mds-changelog/) records an R3→R46 cross-certificate transition beginning 2026-08-31. The current six-certificate chain limit accommodates it; operators would need to add R46 to trust and migrate before the recorded 2029-03-18 expiry of the old R3 path.

The core does **not** implement durable snapshots, high-water state, atomic replacement, scheduled fetch, failure alerts, or existing-credential reassessment. Product MDS remains disabled. Complete and test the adapter before operating with `required_trusted` provenance policy.
