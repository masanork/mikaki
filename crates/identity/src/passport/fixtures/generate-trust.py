"""Independent synthetic CSCA/DSC/CMS/CRL fixtures; private keys stay temporary.

Run: python3 generate-trust.py /opt/homebrew/opt/openssl@3/bin/openssl
"""
from pathlib import Path
from datetime import datetime, timedelta, timezone
import hashlib
import subprocess
import sys
import tempfile

OUT = Path(__file__).resolve().parent
SSL = sys.argv[1] if len(sys.argv) > 1 else 'openssl'

def run(*args):
    result = subprocess.run([SSL, *map(str, args)], stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)
    if result.returncode:
        raise RuntimeError(result.stderr.decode())

def tlv(tag, value):
    n = len(value)
    size = bytes([n]) if n < 128 else bytes([0x80 + (n.bit_length()+7)//8]) + n.to_bytes((n.bit_length()+7)//8, 'big')
    return bytes([tag]) + size + value

def seq(*v): return tlv(0x30, b''.join(v))
def number(n): return tlv(2, bytes([n]))

dg1 = OUT.joinpath('dg1.bin').read_bytes()
algorithm = seq(tlv(6, bytes.fromhex('608648016503040201')), tlv(5, b''))
lds = seq(number(0), algorithm, seq(seq(number(1), tlv(4, hashlib.sha256(dg1).digest())), seq(number(2), tlv(4, hashlib.sha256(b'UNREAD SYNTHETIC DG2').digest()))))
with tempfile.TemporaryDirectory(prefix='mikaki-passport-trust-') as directory:
    tmp = Path(directory)
    for family in ['rsa', 'p256', 'p384']:
        folder = tmp/family
        folder.mkdir()
        def p(name): return folder/name
        p('index').touch()
        p('serial').write_text('02\n')
        p('crlnumber').write_text('01\n')
        digest = 'sha384' if family == 'p384' else 'sha256'
        config = f'''[ca]
default_ca = local
[local]
database = {p('index')}
serial = {p('serial')}
crlnumber = {p('crlnumber')}
new_certs_dir = {folder}
certificate = {p('root.pem')}
private_key = {p('root.key')}
default_md = {digest}
default_days = 3650
default_crl_days = 1
policy = policy
x509_extensions = dsc
crl_extensions = crl
[policy]
countryName = match
organizationName = supplied
commonName = supplied
[dsc]
basicConstraints = critical,CA:FALSE
keyUsage = critical,digitalSignature
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid:always
[crl]
authorityKeyIdentifier = keyid:always
'''
        p('ca.cnf').write_text(config)
        for role in ['root', 'dsc']:
            extra = ['-algorithm', 'RSA', '-pkeyopt', 'rsa_keygen_bits:2048'] if family == 'rsa' else ['-algorithm', 'EC', '-pkeyopt', 'ec_paramgen_curve:'+('P-384' if family == 'p384' else 'P-256'), '-pkeyopt', 'ec_param_enc:explicit']
            run('genpkey', *extra, '-out', p(role+'.key'))
        run('req', '-new', '-x509', '-key', p('root.key'), '-subj', '/C=ZZ/O=Mikaki synthetic fixtures/CN=Synthetic CSCA', '-set_serial', '1', '-days', '3650', '-'+digest, '-addext', 'basicConstraints=critical,CA:TRUE,pathlen:0', '-addext', 'keyUsage=critical,keyCertSign,cRLSign', '-addext', 'subjectKeyIdentifier=hash', '-out', p('root.pem'))
        run('req', '-new', '-key', p('dsc.key'), '-subj', '/C=ZZ/O=Mikaki synthetic fixtures/CN=Synthetic document signer', '-out', p('dsc.csr'))
        run('ca', '-batch', '-config', p('ca.cnf'), '-in', p('dsc.csr'), '-out', p('dsc.pem'))
        for role in ['root', 'dsc']:
            run('x509', '-in', p(role+'.pem'), '-outform', 'DER', '-out', OUT/f'trust-{family}-{role}.der')
        # OpenSSL's TLS certificate policy rejects explicit EC parameters;
        # verify the certificate's exact DER TBS signature directly instead.
        def item(data, offset=0):
            start = offset
            size = data[offset+1]
            offset += 2
            if size & 128:
                n = size & 127
                size = int.from_bytes(data[offset:offset+n], 'big')
                offset += n
            return data[start:offset+size], data[offset:offset+size], offset+size
        cert = OUT.joinpath(f'trust-{family}-dsc.der').read_bytes()
        _, body, _ = item(cert)
        tbs, _, offset = item(body)
        _, _, offset = item(body, offset)
        _, sig, _ = item(body, offset)
        assert sig[0] == 0
        p('tbs.der').write_bytes(tbs)
        p('signature.bin').write_bytes(sig[1:])
        run('pkey', '-in', p('root.key'), '-pubout', '-out', p('root.pub'))
        run('dgst', '-'+digest, '-verify', p('root.pub'), '-signature', p('signature.bin'), p('tbs.der'))
        p('lds.der').write_bytes(lds)
        run('cms', '-sign', '-binary', '-nodetach', '-nosmimecap', '-md', digest, '-econtent_type', '2.23.136.1.1.1', '-in', p('lds.der'), '-signer', p('dsc.pem'), '-inkey', p('dsc.key'), '-outform', 'DER', '-out', p('cms.der'))
        run('cms', '-verify', '-binary', '-inform', 'DER', '-in', p('cms.der'), '-noverify', '-out', p('verified.der'))
        assert p('verified.der').read_bytes() == lds
        OUT.joinpath(f'trust-{family}.sod').write_bytes(tlv(0x77, p('cms.der').read_bytes()))
        now = datetime.now(timezone.utc) + timedelta(seconds=60)
        start, end = now.strftime('%Y%m%d%H%M%SZ'), (now+timedelta(days=1)).strftime('%Y%m%d%H%M%SZ')
        clean_index = p('index').read_bytes()
        for state in ['good', 'revoked', 'root-revoked']:
            p('index').write_bytes(clean_index)
            if state != 'good':
                run('ca', '-config', p('ca.cnf'), '-revoke', p('dsc.pem' if state == 'revoked' else 'root.pem'))
            run('ca', '-gencrl', '-config', p('ca.cnf'), '-crl_lastupdate', start, '-crl_nextupdate', end, '-out', p('crl.pem'))
            run('crl', '-in', p('crl.pem'), '-CAfile', p('root.pem'), '-verify', '-outform', 'DER', '-out', OUT/f'trust-{family}-{state}.crl')
print('Generated three synthetic chains, SODs and signed good/revoked CRLs; independently verified by OpenSSL')
