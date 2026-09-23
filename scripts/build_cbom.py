"""Emit a source-reviewed CycloneDX 1.7 cryptography inventory for the Worker."""

import json
import os
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path
from uuid import NAMESPACE_URL, uuid5

ROOT = Path(__file__).resolve().parents[1]

# These are cryptographic capabilities in the Worker artifact. Runtime TLS is
# supplied by Cloudflare and is outside this source inventory. Never include
# JWK values, passkeys, client secrets, or token material in a CBOM.
ASSETS = (
    (
        "ES256",
        "algorithm",
        {"primitive": "signature", "algorithmFamily": "ECDSA", "cryptoFunctions": ["sign", "verify"]},
        "crates/oidc/src/signing.rs",
        'alg: "ES256"',
    ),
    (
        "RS256",
        "algorithm",
        {"primitive": "signature", "algorithmFamily": "RSASSA-PKCS1", "cryptoFunctions": ["sign", "verify"]},
        "crates/oidc/src/signing.rs",
        'alg: Some("RS256".into())',
    ),
    (
        "SHA-256",
        "algorithm",
        {"primitive": "hash", "algorithmFamily": "SHA-2", "cryptoFunctions": ["digest"]},
        "crates/oidc/src/code.rs",
        "Sha256::digest",
    ),
    (
        "Ed25519 verifier",
        "algorithm",
        {"primitive": "signature", "algorithmFamily": "EdDSA", "cryptoFunctions": ["verify"]},
        "crates/webauthn/src/key.rs",
        "Ed25519",
    ),
    (
        "OP signing private key binding",
        "related-crypto-material",
        {"type": "private-key", "id": "OP_PRIVATE_JWK", "securedBy": {"mechanism": "Software"}},
        "crates/worker/src/lib.rs",
        '.secret("OP_PRIVATE_JWK")',
    ),
    (
        "OP signing public keys",
        "related-crypto-material",
        {"type": "public-key", "id": "signing_key.public_jwk"},
        "crates/worker/migrations/0001_oidc_initial.sql",
        "public_jwk TEXT NOT NULL",
    ),
)


def main() -> None:
    revision = os.environ.get("GITHUB_SHA") or subprocess.check_output(
        ["git", "rev-parse", "HEAD"], cwd=ROOT, text=True
    ).strip()
    epoch = os.environ.get("SOURCE_DATE_EPOCH")
    created = (
        datetime.fromtimestamp(int(epoch), timezone.utc)
        if epoch
        else datetime.now(timezone.utc)
    )
    timestamp = created.isoformat().replace("+00:00", "Z")
    components = []
    for name, asset_type, properties, source, marker in ASSETS:
        if marker not in (ROOT / source).read_text():
            raise SystemExit(f"CBOM source marker missing: {name} ({source})")
        crypto = {"assetType": asset_type}
        field = "algorithmProperties" if asset_type == "algorithm" else "relatedCryptoMaterialProperties"
        crypto[field] = properties
        components.append({
            "type": "cryptographic-asset",
            "name": name,
            "bom-ref": f"crypto:{name.lower().replace(' ', '-')}",
            "cryptoProperties": crypto,
            "properties": [{"name": "mikaki:source", "value": source}],
        })
    document = {
        "bomFormat": "CycloneDX",
        "specVersion": "1.7",
        "serialNumber": f"urn:uuid:{uuid5(NAMESPACE_URL, 'mikaki-worker-cbom:' + revision)}",
        "version": 1,
        "metadata": {
            "timestamp": timestamp,
            "component": {"type": "application", "name": "mikaki-worker", "version": revision},
        },
        "components": components,
    }
    json.dump(document, sys.stdout, indent=2)
    sys.stdout.write("\n")


if __name__ == "__main__":
    main()
