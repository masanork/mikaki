# Synthetic fixed test keys; never use these identities in a deployment.
from pathlib import Path
from datetime import datetime, timezone
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID, ObjectIdentifier
HERE = Path(__file__).parent
START = datetime(2026, 1, 1, tzinfo=timezone.utc)
END = datetime(2036, 1, 1, tzinfo=timezone.utc)
PURPOSE = ObjectIdentifier('1.0.18013.5.1.6')
serial = 100
def key(n): return ec.derive_private_key(int.from_bytes(bytes([n])*32, 'big'), ec.SECP256R1())
def name(n): return x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, n)])
def issue(filename, n, issuer, issuer_key, ca=False, path=None, dns='verifier.example', purpose=PURPOSE, start=START, end=END, cert_sign=None, unknown=False, constraints=False, ca_purpose=None, subject=None):
    global serial
    serial += 1
    b = x509.CertificateBuilder().subject_name(name(filename) if subject is None else subject).issuer_name(issuer).public_key(key(n).public_key()).serial_number(serial).not_valid_before(start).not_valid_after(end)
    b = b.add_extension(x509.BasicConstraints(ca=ca, path_length=path), critical=True)
    b = b.add_extension(x509.KeyUsage(digital_signature=not ca, content_commitment=False, key_encipherment=False, data_encipherment=False, key_agreement=False, key_cert_sign=ca if cert_sign is None else cert_sign, crl_sign=ca, encipher_only=None, decipher_only=None), critical=True)
    if ca:
        if ca_purpose is not None: b = b.add_extension(x509.ExtendedKeyUsage([ca_purpose]), critical=True)
        if constraints: b = b.add_extension(x509.NameConstraints([x509.DNSName('verifier.example')], None), critical=True)
    else:
        if purpose is not None: b = b.add_extension(x509.ExtendedKeyUsage([purpose]), critical=True)
        if dns is not None: b = b.add_extension(x509.SubjectAlternativeName([x509.DNSName(dns)]), critical=False)
    if unknown: b = b.add_extension(x509.UnrecognizedExtension(ObjectIdentifier('1.2.3.4.5.6.7'), b'\x05\x00'), critical=True)
    cert = b.sign(issuer_key, hashes.SHA256())
    (HERE/(filename+'.der')).write_bytes(cert.public_bytes(serialization.Encoding.DER))
    return cert
root = issue('root', 7, name('root'), key(7), ca=True, path=1)
inter = issue('intermediate', 8, root.subject, key(7), ca=True, path=0, constraints=True)
issue('leaf', 5, inter.subject, key(8))
issue('reader', 4, inter.subject, key(8))
issue('wrong-san', 5, inter.subject, key(8), dns='evil.example')
issue('wrong-eku', 5, inter.subject, key(8), purpose=ObjectIdentifier('1.0.18013.5.1.2'))
issue('unknown-critical', 5, inter.subject, key(8), unknown=True)
issue('expired', 5, inter.subject, key(8), start=datetime(2020,1,1,tzinfo=timezone.utc), end=datetime(2021,1,1,tzinfo=timezone.utc))
issue('future', 5, inter.subject, key(8), start=datetime(2037,1,1,tzinfo=timezone.utc), end=datetime(2038,1,1,tzinfo=timezone.utc))
issue('ca-leaf', 5, inter.subject, key(8), ca=True)
issue('bad-ca', 8, root.subject, key(7), ca=True, path=0, cert_sign=False)
sub = issue('sub-ca', 9, inter.subject, key(8), ca=True, path=0)
issue('too-deep', 5, sub.subject, key(9))
issue('wrong-root', 9, name('wrong-root'), key(9), ca=True, path=1)

issue('wildcard', 5, inter.subject, key(8), dns='*.verifier.example')
issue('missing-san', 5, inter.subject, key(8), dns=None)
issue('missing-eku', 5, inter.subject, key(8), purpose=None)

issue('wrong-ca-eku', 8, root.subject, key(7), ca=True, path=0, ca_purpose=ObjectIdentifier('1.0.18013.5.1.2'), subject=inter.subject)
issue('wrong-root-eku', 7, root.subject, key(7), ca=True, path=1, ca_purpose=ObjectIdentifier('1.0.18013.5.1.2'), subject=root.subject)
