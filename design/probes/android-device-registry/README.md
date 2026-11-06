# Android installation registry: local D1 experiment

Run `node --test design/probes/android-device-registry/registry.test.mjs`.
Two local Miniflare Workers share one local D1 database. The experiment checks
that a pending enrollment can be consumed once only by its original, still-live
session, owner and previously verified key; enrollment expiry and key uniqueness
are rechecked in the same batch as device insertion. A failed insertion rolls
the consumption back. Revocation uses owner/session and revision conditions;
only one concurrent revocation can win. Retrying an unobserved successful
enrollment does not create another device.

`verified-proof.test.mjs` additionally makes a real P-256 DPoP signature and
uses the Rust host verifier plus installation binding code before feeding the
verified key, nonce digest and proof ID digest into the local D1 fixture. It
checks forged signatures, nonce mismatch, a changed pending nonce, revoked
fixture session and replay. The host process and fixture share test-supplied
pending state; they are not a deployed Worker or proof that verification and
production persistence are atomic. The fixture accepts caller-supplied
verification outputs and must never be exposed as an application endpoint.

All identities, keys, sessions, clocks and proof results are synthetic test
inputs. This fixture is intentionally not routed into the product. It does not
generate challenges, validate signatures, implement user consent, rate limiting,
authorization of session refresh, replay protection, D1 production timing,
device-key custody, backup or recovery. It is not an RFC 8628 implementation and
does not replace the separate Messenger device registry. A production adapter
must use server time, real account/credential/session authority in the commit,
purpose-bound proofs and durable replay protection, retention and capacity
limits, safe unknown-outcome reconciliation, and a reviewed schema/migration.
It must define how installation revocation affects active sessions and how
installation and Messenger device lifecycles relate without sharing keys.
