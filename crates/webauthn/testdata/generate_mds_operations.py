"""Independent ES256/RS256 MDS operation fixtures. Private keys stay in memory."""
import base64, copy, datetime as dt, json, pathlib
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, rsa, padding, utils
from cryptography.x509.oid import NameOID
B=lambda b:base64.urlsafe_b64encode(b).decode().rstrip('=')
DER=serialization.Encoding.DER
start=dt.datetime(2026,1,1,tzinfo=dt.timezone.utc)
end=dt.datetime(2030,1,1,tzinfo=dt.timezone.utc)
NOW=int(dt.datetime(2026,9,29,tzinfo=dt.timezone.utc).timestamp())
name=lambda s:x509.Name([x509.NameAttribute(NameOID.COMMON_NAME,s)])
root_key=ec.generate_private_key(ec.SECP384R1())
root_name=name('Mikaki operation test root')
def cert(key,subject,ca):
 b=x509.CertificateBuilder().subject_name(subject).issuer_name(root_name).public_key(key.public_key()).serial_number(x509.random_serial_number()).not_valid_before(start).not_valid_after(end)
 b=b.add_extension(x509.BasicConstraints(ca=ca,path_length=None),True)
 b=b.add_extension(x509.KeyUsage(digital_signature=not ca,content_commitment=False,key_encipherment=False,data_encipherment=False,key_agreement=False,key_cert_sign=ca,crl_sign=ca,encipher_only=None,decipher_only=None),True)
 b=b.add_extension(x509.CRLDistributionPoints([x509.DistributionPoint(full_name=[x509.UniformResourceIdentifier('https://mds.example/root.crl')],relative_name=None,reasons=None,crl_issuer=None)]),False)
 return b.sign(root_key,hashes.SHA384())
root=cert(root_key,root_name,True)
crl=x509.CertificateRevocationListBuilder().issuer_name(root_name).last_update(start).next_update(end).sign(root_key,hashes.SHA384())
payload={'no':1,'entries':[{'aaguid':'09090909-0909-0909-0909-090909090909','timeOfLastStatusChange':'2026-09-29','statusReports':[{'status':'FIDO_CERTIFIED'}],'metadataStatement':{'aaguid':'09090909-0909-0909-0909-090909090909','attestationTypes':['basic_full'],'attestationRootCertificates':[base64.b64encode(root.public_bytes(DER)).decode()]}}]}
cases=[]
def add(label,key,leaf,alg,no=1,iat=NOW,legacy=False,ok=True,header_alg=None):
 h={'alg':header_alg or alg,'x5c':[base64.b64encode(leaf.public_bytes(DER)).decode()]}
 if iat is not None:h['iat']=iat
 p=copy.deepcopy(payload);p['no']=no
 if legacy:p['nextUpdate']='2029-01-01'
 signed=B(json.dumps(h).encode())+'.'+B(json.dumps(p).encode())
 if alg=='RS256':signature=key.sign(signed.encode(),padding.PKCS1v15(),hashes.SHA256())
 else:
  r,s=utils.decode_dss_signature(key.sign(signed.encode(),ec.ECDSA(hashes.SHA256())));signature=r.to_bytes(32,'big')+s.to_bytes(32,'big')
 input={'profile':'mds3.0' if legacy else 'mds3.1.1','jwt':signed+'.'+B(signature),'anchor_spki':B(root_key.public_key().public_bytes(DER,serialization.PublicFormat.SubjectPublicKeyInfo)),'now':NOW,'crls':[B(crl.public_bytes(DER))]}
 cases.append({'name':label,'ok':ok,'input':input})
for alg,key in [('ES256',ec.generate_private_key(ec.SECP256R1())),('RS256',rsa.generate_private_key(public_exponent=65537,key_size=2048))]:
 leaf=cert(key,name(alg+' signer'),False)
 for no in [1,2,3]:add(alg+' number '+str(no),key,leaf,alg,no=no)
 add(alg+' same number different content',key,leaf,alg,no=2,iat=NOW+1)
 add(alg+' legacy',key,leaf,alg,iat=None,legacy=True)
 add(alg+' algorithm mismatch',key,leaf,alg,header_alg='ES256' if alg=='RS256' else 'RS256',ok=False)
 add(alg+' unsupported algorithm',key,leaf,alg,header_alg='HS256',ok=False)
path=pathlib.Path(__file__).with_name('mds-operations.json')
path.write_text(json.dumps(cases,separators=(',',':'))+'\n')
print(path,path.stat().st_size)
