# Fixed synthetic fixture keys. CRLs are for tests only, never deployment material.
from pathlib import Path
from datetime import datetime, timezone
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import ObjectIdentifier
HERE = Path(__file__).parent
def key(n): return ec.derive_private_key(int.from_bytes(bytes([n])*32, 'big'), ec.SECP256R1())
def date(y,m,d): return datetime(y,m,d,tzinfo=timezone.utc)
def cert(n): return x509.load_der_x509_certificate((HERE/(n+'.der')).read_bytes())
root, inter, leaf, reader = [cert(n) for n in ('root','intermediate','leaf','reader')]
def issue(name, issuer, n, revoked=(), start=date(2026,9,30), end=date(2026,10,7), kind=None, signing=None):
    b = x509.CertificateRevocationListBuilder().issuer_name(issuer.subject).last_update(start).next_update(end)
    if kind != 'missing-aki': b = b.add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key(key(n).public_key()), critical=False)
    if kind != 'missing-number': b = b.add_extension(x509.CRLNumber(1), critical=False)
    for certificate in revoked:
        b = b.add_revoked_certificate(x509.RevokedCertificateBuilder().serial_number(certificate.serial_number).revocation_date(start).build())
    if kind == 'delta': b = b.add_extension(x509.DeltaCRLIndicator(0), critical=True)
    if kind == 'indirect': b = b.add_extension(x509.IssuingDistributionPoint(None,None,False,False,None,True,False), critical=True)
    if kind == 'unknown-critical': b = b.add_extension(x509.UnrecognizedExtension(ObjectIdentifier('1.2.3.4.5.6.7'), b'\x05\x00'), critical=True)
    crl = b.sign(key(n if signing is None else signing), hashes.SHA256())
    (HERE/(name+'.crl')).write_bytes(crl.public_bytes(serialization.Encoding.DER))
issue('clean-intermediate', inter, 8)
issue('clean-root', root, 7)
issue('revoked-leaf', inter, 8, [leaf])
issue('revoked-reader', inter, 8, [reader])
issue('revoked-intermediate', root, 7, [inter])
issue('expired', inter, 8, start=date(2026,9,1), end=date(2026,9,2))
issue('future', inter, 8, start=date(2030,10,1), end=date(2030,10,8))
issue('stale', inter, 8, start=date(2026,8,1), end=date(2026,11,1))
issue('wrong-key', inter, 8, signing=9)
issue('wrong-issuer', cert('wrong-root'), 9)
for kind in ('delta','indirect','unknown-critical','missing-aki','missing-number'):
    issue(kind, inter, 8, kind=kind)
