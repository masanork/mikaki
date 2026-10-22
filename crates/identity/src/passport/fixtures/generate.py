"""Generate synthetic ICAO LDS/CMS fixtures with independent OpenSSL 3 tooling.

Public test evidence only. Private test keys stay in a temporary directory.
Run with: python3 generate.py [path-to-openssl]
"""
from pathlib import Path
import hashlib
import subprocess
import sys
import tempfile

OUT = Path(__file__).resolve().parent
OPENSSL = sys.argv[1] if len(sys.argv) > 1 else "openssl"

def tlv(tag, value):
    n = len(value)
    size = bytes([n]) if n < 128 else bytes([0x80 + (n.bit_length()+7)//8]) + n.to_bytes((n.bit_length()+7)//8, 'big')
    return bytes([tag]) + size + value

def seq(*values): return tlv(0x30, b''.join(values))
def number(n): return tlv(2, bytes([n]))
def run(*args):
    subprocess.run([OPENSSL, *map(str,args)], check=True, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)

line1 = 'P<UTOERIKSSON<<ANNA<MARIA'.ljust(44, '<')
line2 = 'L898902C<3UTO6908061F9406236<<<<<<<<<<<<<<02'
assert len(line2) == 44
dg1 = bytes([0x61,91,0x5f,0x1f,88]) + (line1+line2).encode('ascii')
OUT.joinpath('dg1.bin').write_bytes(dg1)
hash_alg = seq(tlv(6,bytes.fromhex('608648016503040201')), tlv(5,b''))
lds = seq(number(0),hash_alg,seq(seq(number(1),tlv(4,hashlib.sha256(dg1).digest())),seq(number(2),tlv(4,hashlib.sha256(b'UNREAD SYNTHETIC DG2').digest()))))
with tempfile.TemporaryDirectory(prefix='mikaki-passport-sod-') as tmp:
    tmp = Path(tmp)
    tmp.joinpath('lds.der').write_bytes(lds)
    for family in ['rsa','p256']:
        key, cert = tmp/f'{family}.key', tmp/f'{family}.pem'
        run('genpkey','-algorithm', 'RSA' if family == 'rsa' else 'EC', '-pkeyopt', 'rsa_keygen_bits:2048' if family == 'rsa' else 'ec_paramgen_curve:P-256','-out',key)
        run('req','-new','-x509','-key',key,'-subj','/C=ZZ/O=Mikaki synthetic fixtures/CN=Untrusted document signer','-days','1','-sha256','-addext','basicConstraints=critical,CA:FALSE','-addext','keyUsage=critical,digitalSignature','-out',cert)
        variants = [(family+'-'+digest,digest,[]) for digest in (['sha256','sha384','sha512'] if family == 'rsa' else ['sha256'])]
        if family == 'rsa': variants += [('pss-'+digest,digest,['-keyopt','rsa_padding_mode:pss','-keyopt','rsa_pss_saltlen:digest']) for digest in ['sha256','sha384','sha512']]
        if family == 'p256': variants += [('p256-keyid','sha256',['-keyid'])]
        for name,digest,extra in variants:
            cms = tmp/f'{name}.cms'
            run('cms','-sign','-binary','-nodetach','-nosmimecap','-md',digest,'-econtent_type','2.23.136.1.1.1','-in',tmp/'lds.der','-signer',cert,'-inkey',key,'-outform','DER','-out',cms,*extra)
            run('cms','-verify','-binary','-inform','DER','-in',cms,'-noverify','-out',tmp/'verified.der')
            assert tmp.joinpath('verified.der').read_bytes() == lds
            OUT.joinpath(name+'.sod').write_bytes(tlv(0x77,cms.read_bytes()))
print('Generated DG1 and eight independently verified CMS fixtures')
