# Vault recipient key and envelope format

**Candidate, 2026-09-24. No product envelope may be written in this format yet.** The active generation-1 UserInfo key is a raw ML-KEM-768 encapsulation key, not an OIDC signing key or a JWK. The independent claim Worker holds its 64-byte decapsulation seed. This document fixes the byte-level questions that the isolated probe must answer before a storage migration and sharing endpoint are added. The [independent Node harness](../design/probes/pqc/hpke-interop.ts) now opens a RustCrypto HPKE AES-256-GCM fixture with noble ML-KEM and Node crypto, and RustCrypto opens one produced by noble and Node. The [claim Worker unit test](../crates/userinfo-claim-worker/src/lib.rs) decodes the same public fixture seed through its canonical seed validator and opens the checked-in noble envelope. These tests use the probe's draft-04 domain label; they do not exercise a live Secrets Store binding.

## Existing key record

The D1 directory returns the 1,184-byte raw public encapsulation key as canonical unpadded base64url. `key_id` is canonical unpadded base64url of SHA-256 over those **raw bytes**. `generation` is a positive, monotonically increasing integer for the `userinfo` service. The private Secrets Store value is the 64-byte ML-KEM seed (`d || z`), also encoded as canonical unpadded base64url; it is never part of an envelope or browser response. The public key, 64-byte private seed, and 1,088-byte encapsulation are the [ML-KEM-768 sizes and serialization defined by the current HPKE PQ draft](https://datatracker.ietf.org/doc/html/draft-ietf-hpke-pq-05#section-3). The key ID identifies the raw public key, while the generation identifies its place in the service's rotation history; neither alone identifies an HPKE suite.

The directory's `algorithm: ML-KEM-768` describes only the KEM key. A client must never infer permission to use a new HPKE KDF, AEAD, draft revision, or recipient purpose from that value. A future directory revision needs an explicit allowed envelope suite before the browser can create one. The existing key may be reused only after a receiver using its actual Secrets Store seed passes the selected suite's interoperability tests. If the draft changes the key interpretation, generate and activate a new key instead.

## Candidate envelope v1

The candidate uses HPKE base mode with KEM `0x0041` (ML-KEM-768), KDF `0x0001` (HKDF-SHA256), and AEAD `0x0002` (AES-256-GCM). These are [HPKE registry identifiers](https://www.iana.org/assignments/hpke) and the [PQ draft's ML-KEM-768 identifier](https://datatracker.ietf.org/doc/html/draft-ietf-hpke-pq-05#section-8.1). Base mode does **not** authenticate the sender; owner SSO, PRF unlock, request binding, revision checks, Grant creation, and audit must do that outside HPKE. No sender private key is implied.

One envelope wraps exactly one 32-byte Vault data key. The 1,088-byte HPKE `enc` and 48-byte `ct` (32-byte plaintext plus 16-byte GCM tag) are separate values. An envelope record must carry the following fields, with exact lengths and no omitted or unknown security fields:

| Field | Candidate encoding | Purpose |
| --- | --- | --- |
| `format_version` | integer `1` | Reject unknown parsers and future changes |
| `kem_id`, `kdf_id`, `aead_id` | unsigned 16-bit identifiers above | Bind the complete suite |
| `recipient_service` | exact ASCII `userinfo` | Separate services |
| `recipient_key_id` | 32 raw digest bytes or canonical 43-character base64url | Select the matching D1 key and Secrets Store binding |
| `recipient_generation` | positive unsigned 64-bit integer | Reject retired/offline keys |
| `enc` | exactly 1,088 raw bytes | HPKE encapsulation |
| `ct` | exactly 48 raw bytes | Encrypted data key |

The isolated probe exercises one candidate binary frame. Its exact 1,187-byte layout is `MKVE` (4 bytes), version `01` (1), KEM/KDF/AEAD IDs in network byte order (6), raw key-ID digest (32), generation in network byte order (8), `enc` (1,088), and `ct` (48). It rejects other total lengths, unknown version or suite, and key identity or generation mismatches before HPKE. Changed `enc` or `ct` must fail authenticated decryption. This frame is an experiment, not a production serialization commitment.

If JSON is used at the HTTP edge, binary fields use canonical unpadded base64url. D1 should store the binary values and indexed metadata separately; JSON property order must have no cryptographic meaning. The product format should be frozen only after both browser and claim Worker parse the same adversarial fixture set.

HPKE `info` is an unambiguous length-prefixed sequence of a domain label, format version, the six suite-ID bytes, service ID, 32 raw key-ID bytes, and big-endian generation. The probe's current domain label explicitly ends in `draft04`; production must pick a label tied to the specification revision that passes interoperability. AEAD `aad` is an unambiguous length-prefixed sequence of issuer origin, verified account ID, attribute ID, unsigned 64-bit Vault revision, recipient service, recipient purpose (initially `oidc.userinfo.name`), and SHA-256 of the exact stored Vault ciphertext bytes. Each part uses a two-byte big-endian byte length followed by the bytes; no locale-dependent normalization or string concatenation. The claim Worker must derive these values from trusted request/D1 state and compare the envelope fields to the selected key. It must not accept caller-provided `info` or `aad` as authority.

Binding the ciphertext digest prevents a valid wrapped data key from being attached to a different blob that happens to have the same attribute revision. The envelope is valid only for the exact account, attribute, revision, purpose, recipient key, and ciphertext. A new attribute revision requires a new recipient envelope. Disabling a key or Grant stops unwrap even when old envelope bytes remain in D1. The version and suite values must be checked **before** HPKE processing; no automatic downgrade or trial decryption across suites.

## Gate before product storage

1. CI runs the bidirectional RustCrypto↔noble/Node AES-256-GCM fixture check, and the claim Worker unit test opens the checked-in noble fixture after canonical seed decoding. Exercise the same operation through an actual Secrets Store binding and a separate browser implementation. The existing [draft-05 vector](../design/probes/pqc/hpke-pq-draft05-vector.json) covers AES-128-GCM only; it and the bidirectional draft-04 probe do not establish full draft-05 AES-256-GCM compatibility.
2. Reject changed version/suite/key ID/generation, account, attribute, revision, purpose, ciphertext digest, encapsulation, tag, truncated values, noncanonical base64url, and trailing bytes. Check that a directory key rotation never silently rewrites the envelope's key identity.
3. Verify the claim Worker accepts only its internal authenticated caller, current D1 key state, and a live matching Grant. Test revocation racing an unwrap and loss of the Secrets Store seed. No UserInfo claim is released on any failure.
4. Freeze the format with a suite identifier that names the exact HPKE PQ specification revision used for interoperability. A later RFC or library change needs a new format/suite ID and a migration plan. Keep all current probe outputs outside product storage until this gate passes.

The [HPKE PQ document is still an Internet-Draft](https://datatracker.ietf.org/doc/draft-ietf-hpke-pq/). The isolated `hpke` crate probe currently describes its KEM as draft-04; opening one draft-05 AES-128-GCM vector is useful evidence for the key representation, not a full compatibility claim for this candidate.
