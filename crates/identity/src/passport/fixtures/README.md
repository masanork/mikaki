# Synthetic passport signature fixtures

These are synthetic TD3 DG1 and EF.SOD files, not real passport data or trusted issuers.
`generate.py` constructs the LDS hashes independently and uses OpenSSL 3 to create
RSA PKCS#1, RSA-PSS and P-256 CMS SignedData. It also verifies each CMS with OpenSSL.
Private test keys exist only in a temporary directory and are not retained.

Regenerate with `python3 generate.py /path/to/openssl3`. Generated certificates,
signatures and signing times change each run; tests check their cryptographic
relationships without treating certificate dates or self-signatures as issuer trust.
Eight cases cover SHA-256/384/512 for RSA and PSS, plus P-256 with issuer/serial and
SKI identifiers. Only DG1 is available; the dummy DG2 hash cannot qualify DG2 reading.


`generate-trust.py` additionally creates synthetic CSCA -> DSC paths and complete
CRLs for RSA/SHA-256, explicit P-256/SHA-256 and explicit P-384/SHA-384. Each includes
a DG1 SOD, a good CRL, a DSC-revoked CRL and a CSCA-revoked CRL. Certificate TBS
signatures, CMS signatures and CRL signatures are independently verified by OpenSSL 3.
Its TLS-oriented CMS certificate policy rejects explicit EC parameters, so that
script verifies the exact DSC TBS signature directly with `openssl dgst` and verifies
CMS with `-noverify`. This bypass applies only to the synthetic fixture generator;
the shared verifier performs the explicit-domain and CSCA path checks itself.
Tests use the fixed generated CRL's time and assert stale/future/certificate-expired
behavior separately. No test trusts these synthetic roots in the production policy.
Private keys remain temporary; regeneration changes the synthetic signatures and dates.
