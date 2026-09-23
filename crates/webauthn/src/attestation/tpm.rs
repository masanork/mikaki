//! Length-delimited TPM structures; no byte searching or ignored suffixes.
use super::*;
use rsa::traits::PublicKeyParts;
use x509_cert::ext::pkix::{ExtendedKeyUsage, SubjectAltName, name::GeneralName};
struct Reader<'a>(&'a [u8]);
impl<'a> Reader<'a> {
    fn take(&mut self, n: usize) -> Result<&'a [u8]> {
        let v = self.0.get(..n).ok_or(Invalid::Tpm)?;
        self.0 = &self.0[n..];
        Ok(v)
    }
    fn u16(&mut self) -> Result<u16> {
        Ok(u16::from_be_bytes(
            self.take(2)?.try_into().map_err(|_| Invalid::Tpm)?,
        ))
    }
    fn u32(&mut self) -> Result<u32> {
        Ok(u32::from_be_bytes(
            self.take(4)?.try_into().map_err(|_| Invalid::Tpm)?,
        ))
    }
    fn blob(&mut self) -> Result<&'a [u8]> {
        let n = usize::from(self.u16()?);
        self.take(n)
    }
    fn end(&self) -> Result<()> {
        require(self.0.is_empty())
    }
    fn symmetric(&mut self) -> Result<()> {
        match self.u16()? {
            0x10 => Ok(()),
            0x6 | 0x13 => {
                self.take(4)?;
                Ok(())
            }
            _ => Err(Invalid::Tpm),
        }
    }
    fn scheme(&mut self) -> Result<()> {
        match self.u16()? {
            0x10 => Ok(()),
            0x14 | 0x16 | 0x18 | 0x19 => {
                self.take(2)?;
                Ok(())
            }
            _ => Err(Invalid::Tpm),
        }
    }
}
fn digest(alg: u16, data: &[u8]) -> Result<Vec<u8>> {
    match alg {
        4 => Ok(sha1::Sha1::digest(data).to_vec()),
        11 => Ok(Sha256::digest(data).to_vec()),
        12 => Ok(sha2::Sha384::digest(data).to_vec()),
        _ => Err(Invalid::Tpm),
    }
}
pub(super) fn verify(s: &Value, key: &PublicKey, signed: &[u8], cert: &Certificate) -> Result<()> {
    let public = bytes(s, "pubArea")?;
    let info = bytes(s, "certInfo")?;
    let alg = algorithm(s)?;
    let mut p = Reader(public);
    let kind = p.u16()?;
    let name_alg = p.u16()?;
    p.take(4)?;
    p.blob()?;
    p.symmetric()?;
    p.scheme()?;
    match (kind, key) {
        (1, PublicKey::Rsa { key, .. }) => {
            let bits = p.u16()?;
            let e = p.u32()?;
            let n = p.blob()?;
            require(
                usize::from(bits) == key.n().bits() as usize && n == key.n().to_be_bytes().as_ref(),
            )?;
            require(rsa::BoxedUint::from(if e == 0 { 65537 } else { e }) == *key.e())?;
        }
        (0x23, PublicKey::Es256(key)) => {
            require(p.u16()? == 3)?;
            require(p.u16()? == 0x10)?;
            let x = p.blob()?;
            let y = p.blob()?;
            let point = key.to_sec1_point(false);
            require(x == &point.as_bytes()[1..33] && y == &point.as_bytes()[33..65])?;
        }
        _ => return Err(Invalid::Tpm),
    }
    p.end()?;
    let mut c = Reader(info);
    require(c.u32()? == 0xff544347 && c.u16()? == 0x8017)?;
    c.blob()?;
    let hash_alg = match alg {
        -7 | -257 => 11,
        -65535 => 4,
        -35 => 12,
        _ => return Err(Invalid::Tpm),
    };
    require(c.blob()? == digest(hash_alg, signed)?)?;
    c.take(16)?;
    require(c.take(1)?[0] <= 1)?;
    c.take(8)?;
    let mut name = name_alg.to_be_bytes().to_vec();
    name.extend(digest(name_alg, public)?);
    require(c.blob()? == name)?;
    c.blob()?;
    c.end()?;
    let tbs = cert.tbs_certificate();
    require(
        tbs.get_extension::<x509_cert::ext::pkix::BasicConstraints>()
            .map_err(|_| Invalid::Tpm)?
            .is_some_and(|(_, b)| !b.ca),
    )?;
    require(tbs.version() == x509_cert::certificate::Version::V3 && tbs.subject().is_empty())?;
    let (_, san) = tbs
        .get_extension::<SubjectAltName>()
        .map_err(|_| Invalid::Tpm)?
        .ok_or(Invalid::Tpm)?;
    let attrs = san
        .0
        .iter()
        .filter_map(|n| {
            if let GeneralName::DirectoryName(n) = n {
                Some(n)
            } else {
                None
            }
        })
        .flat_map(|n| n.iter())
        .collect::<Vec<_>>();
    for oid in ["2.23.133.2.1", "2.23.133.2.2", "2.23.133.2.3"] {
        let values = attrs
            .iter()
            .filter(|a| a.oid.to_string() == oid)
            .collect::<Vec<_>>();
        require(values.len() == 1 && !values[0].value.value().is_empty())?;
    }
    let (_, eku) = tbs
        .get_extension::<ExtendedKeyUsage>()
        .map_err(|_| Invalid::Tpm)?
        .ok_or(Invalid::Tpm)?;
    require(eku.0.iter().any(|oid| oid.to_string() == "2.23.133.8.3"))?;
    certificate::verify(cert, alg, info, bytes(s, "sig")?)
}

fn require(ok: bool) -> Result<()> {
    ensure(ok, Invalid::Tpm)
}
