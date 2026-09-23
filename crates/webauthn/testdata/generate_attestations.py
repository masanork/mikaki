"""Independent public fixtures: Python cryptography/OpenSSL and cbor2.
Private keys exist only in memory. The official FIDO suite is not used here.
Run manually; CI consumes the checked-in JSON, not these optional tools.
"""
import base64, copy, datetime as dt, hashlib, json, pathlib, struct
import cbor2
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, rsa, padding, utils
from cryptography.x509.oid import NameOID, ObjectIdentifier as OID
B = lambda b: base64.urlsafe_b64encode(b).decode().rstrip('=')
DER = serialization.Encoding.DER
NOW = int(dt.datetime(2026, 9, 22, tzinfo=dt.timezone.utc).timestamp())
start = dt.datetime(2026, 1, 1, tzinfo=dt.timezone.utc)
end = dt.datetime(2030, 1, 1, tzinfo=dt.timezone.utc)
name = lambda s: x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, s)])
root_key = ec.generate_private_key(ec.SECP384R1())
inter_key = ec.generate_private_key(ec.SECP256R1())
leaf_key = ec.generate_private_key(ec.SECP256R1())
credential_key = ec.derive_private_key(int.from_bytes(bytes([7])*32, 'big'), ec.SECP256R1())
root_name, inter_name = name('Mikaki test root'), name('Mikaki test intermediate')
packed_name = x509.Name([x509.NameAttribute(NameOID.COUNTRY_NAME,'US'),x509.NameAttribute(NameOID.ORGANIZATION_NAME,'Mikaki tests'),x509.NameAttribute(NameOID.ORGANIZATIONAL_UNIT_NAME,'Authenticator Attestation'),x509.NameAttribute(NameOID.COMMON_NAME,'Independent batch')])
def cert(subject, issuer, key, signer, ca=False, extras=(), include_bc=True):
    b=x509.CertificateBuilder().subject_name(subject).issuer_name(issuer).public_key(key.public_key()).serial_number(x509.random_serial_number()).not_valid_before(start).not_valid_after(end)
    if include_bc:b=b.add_extension(x509.BasicConstraints(ca=ca,path_length=None),critical=True)
    b=b.add_extension(x509.KeyUsage(digital_signature=not ca,content_commitment=False,key_encipherment=False,data_encipherment=False,key_agreement=False,key_cert_sign=ca,crl_sign=ca,encipher_only=None,decipher_only=None),critical=True)
    for value,critical in extras:b=b.add_extension(value,critical)
    return b.sign(signer,hashes.SHA384() if signer==root_key else hashes.SHA256())
root=cert(root_name,root_name,root_key,root_key,True)
inter=cert(inter_name,root_name,inter_key,root_key,True)
leaf=cert(packed_name,inter_name,leaf_key,inter_key)
nums=credential_key.public_key().public_numbers()
cose={1:2,3:-7,-1:1,-2:nums.x.to_bytes(32,'big'),-3:nums.y.to_bytes(32,'big')}
challenge=B(bytes([3])*32)
client=json.dumps({'type':'webauthn.create','challenge':challenge,'origin':'https://login.example','crossOrigin':False},separators=(',',':')).encode()
hash_client=hashlib.sha256(client).digest()
aaguid=bytes([9])*16
header=hashlib.sha256(b'login.example').digest()+b'\x45'+bytes(4)
auth=header+aaguid+b'\x00\x03\x01\x02\x03'+cbor2.dumps(cose)
sign=lambda key,data:key.sign(data,ec.ECDSA(hashes.SHA256()))
context={'challenge':challenge,'origin':'https://login.example','rp_id':'login.example','max_bytes':65536,'max_depth':8,'algorithms':[-7],'attestation':{'now':NOW,'entries':[{'aaguid':B(aaguid),'key_ids':[],'roots':[B(root.public_bytes(DER))],'types':['basic_full','attca'],'allowed':True}]}}
def registration(fmt,statement,data=auth):return {'id':B(b'\x01\x02\x03'),'client_data':B(client),'attestation':B(cbor2.dumps({'fmt':fmt,'attStmt':statement,'authData':data}))}
packed={'alg':-7,'sig':sign(leaf_key,auth+hash_client),'x5c':[leaf.public_bytes(DER),inter.public_bytes(DER)]}
cases=[]
def add(label,ok,response,ctx=context):cases.append({'name':label,'ok':ok,'context':copy.deepcopy(ctx),'response':response})
add('packed chain',True,registration('packed',packed))
for label,mutate in [('untrusted root',lambda c:c['attestation']['entries'][0].update(roots=[])),('expired certificate',lambda c:c['attestation'].update(now=NOW+10*366*86400)),('revoked metadata',lambda c:c['attestation']['entries'][0].update(allowed=False)),('wrong AAGUID',lambda c:c['attestation']['entries'][0].update(aaguid=B(bytes(16))))]:
    ctx=copy.deepcopy(context);mutate(ctx);add(label,False,registration('packed',packed),ctx)
for label,chain in [('reordered chain',[inter.public_bytes(DER),leaf.public_bytes(DER)]),('duplicate chain',[leaf.public_bytes(DER)]*2),('included root',[leaf.public_bytes(DER),inter.public_bytes(DER),root.public_bytes(DER)])]:
    s=copy.deepcopy(packed);s['x5c']=chain;add(label,False,registration('packed',s))
for label,subject,extras in [('wrong OU',name('wrong'),()),('unknown critical',packed_name,[(x509.UnrecognizedExtension(OID('1.2.3.4.5'),b'\x05\x00'),True)]),('mismatched AAGUID extension',packed_name,[(x509.UnrecognizedExtension(OID('1.3.6.1.4.1.45724.1.1.4'),b'\x04\x10'+bytes(16)),False)])]:
    c=cert(subject,inter_name,leaf_key,inter_key,extras=extras);s=copy.deepcopy(packed);s['x5c'][0]=c.public_bytes(DER);add(label,False,registration('packed',s))
for label,c in [('missing Basic Constraints',cert(packed_name,inter_name,leaf_key,inter_key,include_bc=False)),('unsupported policy constraints',cert(packed_name,inter_name,leaf_key,inter_key,extras=[(x509.PolicyConstraints(require_explicit_policy=0,inhibit_policy_mapping=None),False)]))]:
    s=copy.deepcopy(packed);s['x5c'][0]=c.public_bytes(DER);add(label,False,registration('packed',s))
u2f_auth=header+bytes(16)+auth[53:]
u2f_cert=cert(name('U2F'),root_name,leaf_key,root_key)
point=credential_key.public_key().public_bytes(serialization.Encoding.X962,serialization.PublicFormat.UncompressedPoint)
u2f={'sig':sign(leaf_key,b'\x00'+header[:32]+hash_client+b'\x01\x02\x03'+point),'x5c':[u2f_cert.public_bytes(DER)]}
ctx=copy.deepcopy(context);ctx['attestation']['entries'][0]['aaguid']='';ctx['attestation']['entries'][0]['key_ids']=[hashlib.sha1(leaf_key.public_key().public_bytes(serialization.Encoding.X962,serialization.PublicFormat.UncompressedPoint)).hexdigest()]
add('U2F',True,registration('fido-u2f',u2f,u2f_auth),ctx)
u2f['sig']=u2f['sig'][:-1]+bytes([u2f['sig'][-1]^1]);add('U2F signature',False,registration('fido-u2f',u2f,u2f_auth),ctx)
# TPM RSA credential, with independently serialized TPMT_PUBLIC and TPMS_ATTEST.
rsa_key=rsa.generate_private_key(public_exponent=65537,key_size=2048)
rn=rsa_key.public_key().public_numbers();n=rn.n.to_bytes(256,'big')
rcose={1:3,3:-257,-1:n,-2:b'\x01\x00\x01'}
rauth=header+aaguid+b'\x00\x03\x01\x02\x03'+cbor2.dumps(rcose)
aik_key=rsa.generate_private_key(public_exponent=65537,key_size=2048)
san=x509.SubjectAlternativeName([x509.DirectoryName(x509.Name([x509.NameAttribute(OID('2.23.133.2.1'),'id:FFFFF1D0'),x509.NameAttribute(OID('2.23.133.2.2'),'Independent TPM'),x509.NameAttribute(OID('2.23.133.2.3'),'id:00010000')]))])
aik=cert(x509.Name([]),inter_name,aik_key,inter_key,extras=[(san,True),(x509.ExtendedKeyUsage([OID('2.23.133.8.3')]),False)])
blob=lambda b:struct.pack('>H',len(b))+b
public=struct.pack('>HHI',1,11,0x00060472)+blob(b'')+struct.pack('>HHHI',16,16,2048,0)+blob(n)
def info(public=public,extra=None,magic=0xff544347,name_digest=None):return struct.pack('>IH',magic,0x8017)+blob(b'')+blob(extra or hashlib.sha256(rauth+hash_client).digest())+bytes(16)+b'\x01'+bytes(8)+blob(b'\x00\x0b'+(name_digest or hashlib.sha256(public).digest()))+blob(b'')
def tpm(public=public,info=info()):return {'ver':'2.0','alg':-257,'pubArea':public,'certInfo':info,'sig':aik_key.sign(info,padding.PKCS1v15(),hashes.SHA256()),'x5c':[aik.public_bytes(DER),inter.public_bytes(DER)]}
ctx=copy.deepcopy(context);ctx['algorithms']=[-257]
add('TPM RSA',True,registration('tpm',tpm(),rauth),ctx)
for label,s in [('TPM magic',tpm(info=info(magic=1))),('TPM extraData',tpm(info=info(extra=bytes(32)))),('TPM certified name',tpm(info=info(name_digest=bytes(32)))),('TPM modulus',tpm(public=public[:-1]+bytes([public[-1]^1]))),('TPM trailing certInfo',tpm(info=info()+b'\x00'))]:add(label,False,registration('tpm',s,rauth),ctx)
# Signed MDS BLOB and full direct CRLs, independent of FIDO test material.
mds_leaf=cert(name('MDS signer'),inter_name,leaf_key,inter_key)
mds_payload={'no':1,'nextUpdate':'2029-01-01','entries':[{'aaguid':'09090909-0909-0909-0909-090909090909','timeOfLastStatusChange':'2026-01-01','statusReports':[{'status':'FIDO_CERTIFIED','effectiveDate':'2026-01-01','authenticatorVersion':1}],'metadataStatement':{'aaguid':'09090909-0909-0909-0909-090909090909','authenticatorVersion':1,'attestationRootCertificates':[base64.b64encode(root.public_bytes(DER)).decode()],'attestationTypes':['basic_full']}}]}
def jwt(payload,issued_at=NOW,x5u=None):
    header={'alg':'ES256','x5c':[base64.b64encode(c.public_bytes(DER)).decode() for c in [mds_leaf,inter]]}
    if issued_at is not None:header['iat']=issued_at
    if x5u is not None:header['x5u']=x5u
    signed=B(json.dumps(header).encode())+'.'+B(json.dumps(payload).encode());r,s=utils.decode_dss_signature(sign(leaf_key,signed.encode()));return signed+'.'+B(r.to_bytes(32,'big')+s.to_bytes(32,'big'))
def crl(issuer,key,revoked=None):
    b=x509.CertificateRevocationListBuilder().issuer_name(issuer).last_update(start).next_update(end)
    if revoked is not None:b=b.add_revoked_certificate(x509.RevokedCertificateBuilder().serial_number(revoked).revocation_date(start).build())
    return B(b.sign(key,hashes.SHA384() if key==root_key else hashes.SHA256()).public_bytes(DER))
mds={'jwt':jwt(mds_payload),'anchor_spki':B(root_key.public_key().public_bytes(DER,serialization.PublicFormat.SubjectPublicKeyInfo)),'now':NOW,'crls':[crl(inter_name,inter_key),crl(root_name,root_key)]}
mds_cases=[{'name':'valid MDS','ok':True,'input':mds}]
key_id=hashlib.sha1(u2f_cert.public_key().public_bytes(serialization.Encoding.X962,serialization.PublicFormat.UncompressedPoint)).hexdigest()
payload=copy.deepcopy(mds_payload);entry=payload['entries'][0];entry.pop('aaguid');entry['attestationCertificateKeyIdentifiers']=[key_id];entry['metadataStatement'].pop('aaguid');v=copy.deepcopy(mds);v['jwt']=jwt(payload);mds_cases.append({'name':'valid U2F metadata','ok':True,'key_id':key_id,'input':v})
payload=copy.deepcopy(mds_payload);payload['entries'][0]['statusReports']=[{'status':'FUTURE_STATUS'}];v=copy.deepcopy(mds);v['jwt']=jwt(payload);mds_cases.append({'name':'unknown status is retained','ok':True,'status':'FUTURE_STATUS','input':v})
payload=copy.deepcopy(mds_payload);payload.pop('no');v=copy.deepcopy(mds);v['jwt']=jwt(payload);mds_cases.append({'name':'missing BLOB number','ok':False,'input':v})
payload=copy.deepcopy(mds_payload);v=copy.deepcopy(mds);v['jwt']=jwt(payload,None);mds_cases.append({'name':'missing issued-at','ok':False,'input':v})
payload=copy.deepcopy(mds_payload);v=copy.deepcopy(mds);v['jwt']=jwt(payload,x5u='https://mds.example/signer.pem');mds_cases.append({'name':'x5u transport is unsupported','ok':False,'input':v})
for label,mutate in [('revoked signer',lambda m:m['crls'].__setitem__(0,crl(inter_name,inter_key,mds_leaf.serial_number))),('revoked intermediate',lambda m:m['crls'].__setitem__(1,crl(root_name,root_key,inter.serial_number))),('missing CRLs',lambda m:m.update(crls=[])),('wrong anchor',lambda m:m.update(anchor_spki=B(inter_key.public_key().public_bytes(DER,serialization.PublicFormat.SubjectPublicKeyInfo)))),('expired CRL',lambda m:m.update(now=NOW+10*366*86400)),('bad JWT signature',lambda m:m.update(jwt=m['jwt'][:-5]+'AAAAA'))]:
    v=copy.deepcopy(mds);mutate(v);mds_cases.append({'name':label,'ok':False,'input':v})
payload=copy.deepcopy(mds_payload);payload['nextUpdate']='2025-01-01';v=copy.deepcopy(mds);v['jwt']=jwt(payload);mds_cases.append({'name':'past nextUpdate is retained','ok':True,'past_next_update':True,'input':v})
payload=copy.deepcopy(mds_payload);payload.pop('nextUpdate');v=copy.deepcopy(mds);v['jwt']=jwt(payload);mds_cases.append({'name':'missing nextUpdate is accepted','ok':True,'no_next_update':True,'input':v})
payload=copy.deepcopy(mds_payload);payload['entries'][0]['statusReports']=[{'status':'REVOKED'}];v=copy.deepcopy(mds);v['jwt']=jwt(payload);mds_cases.append({'name':'revoked metadata','ok':True,'allowed':False,'input':v})
path=pathlib.Path(__file__).with_name('attestations.json');path.write_text(json.dumps({'registrations':cases,'mds':mds_cases},separators=(',',':'))+'\n');print(path, path.stat().st_size)
