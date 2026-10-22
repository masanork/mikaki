use super::*;
const DG1: &[u8] = include_bytes!("../fixtures/dg1.bin");
const RSA: &[u8] = include_bytes!("../fixtures/rsa-sha256.sod");
#[test]
fn non_der_signed_attribute_order_is_not_silently_normalized() {
    let mut pos = 0;
    let cms = super::super::encoding::value(RSA, &mut pos, &[0x77]).unwrap();
    let info = ContentInfo::from_der(cms).unwrap();
    let signed = info.content.decode_as::<SignedData>().unwrap();
    let attrs = signed.signers.get(0).unwrap().attributes.as_ref().unwrap();
    let mut original = attrs.to_der().unwrap();
    original[0] = 0xa0;
    let pieces = attrs
        .iter()
        .map(|a| a.to_der().unwrap())
        .collect::<Vec<_>>();
    let body_len: usize = pieces.iter().map(Vec::len).sum();
    let mut reversed = original[..original.len() - body_len].to_vec();
    for value in pieces.iter().rev() {
        reversed.extend_from_slice(value);
    }
    let offset = cms
        .windows(original.len())
        .position(|w| w == original)
        .unwrap();
    let mut changed = cms.to_vec();
    changed[offset..offset + reversed.len()].copy_from_slice(&reversed);
    assert_eq!(verify(&wrap(&changed), DG1).state, State::Invalid);
}
fn wrap(cms: &[u8]) -> Vec<u8> {
    let mut out = vec![0x77];
    if cms.len() < 128 {
        out.push(cms.len() as u8);
    } else if cms.len() < 256 {
        out.extend_from_slice(&[0x81, cms.len() as u8]);
    } else {
        out.extend_from_slice(&[0x82, (cms.len() >> 8) as u8, cms.len() as u8]);
    }
    out.extend_from_slice(cms);
    out
}
pub(super) fn mutate(sod: &[u8], edit: impl FnOnce(&mut SignedData)) -> Vec<u8> {
    let mut pos = 0;
    let bytes = super::super::encoding::value(sod, &mut pos, &[0x77]).unwrap();
    let mut info = ContentInfo::from_der(bytes).unwrap();
    let mut signed = info.content.decode_as::<SignedData>().unwrap();
    edit(&mut signed);
    info.content = Any::encode_from(&signed).unwrap();
    wrap(&info.to_der().unwrap())
}
fn signer(signed: &mut SignedData, edit: impl FnOnce(&mut Signer)) {
    let mut values = std::mem::take(&mut signed.signers).into_vec();
    edit(&mut values[0]);
    signed.signers = SetOfVec::try_from(values).unwrap();
}
#[test]
fn independent_openssl_cms_vectors_verify_but_never_establish_issuer_trust() {
    for sod in [
        RSA,
        include_bytes!("../fixtures/rsa-sha384.sod"),
        include_bytes!("../fixtures/rsa-sha512.sod"),
        include_bytes!("../fixtures/pss-sha256.sod"),
        include_bytes!("../fixtures/pss-sha384.sod"),
        include_bytes!("../fixtures/pss-sha512.sod"),
        include_bytes!("../fixtures/p256-sha256.sod"),
        include_bytes!("../fixtures/p256-keyid.sod"),
    ] {
        let report = verify(sod, DG1);
        assert_eq!(report.state, State::Consistent);
        assert_eq!(report.checked_data_groups, [1]);
        assert_eq!(report.issuer_trust, "unknown_issuer");
    }
}
#[test]
fn unchanged_valid_signature_cannot_authenticate_changed_encapsulated_content() {
    // Change only an unread DG2 hash. DG1 and the signature over signedAttrs are
    // unchanged; checking message-digest against eContent is what rejects this.
    let changed = mutate(RSA, |s| {
        let mut lds = Lds::from_der(s.encapsulated.content.as_ref().unwrap().as_bytes()).unwrap();
        lds.hashes[1].hash = OctetString::new(vec![0; 32]).unwrap();
        s.encapsulated.content = Some(OctetString::new(lds.to_der().unwrap()).unwrap());
    });
    assert_eq!(verify(&changed, DG1).state, State::Invalid);
    let mut changed_dg1 = DG1.to_vec();
    changed_dg1[10] ^= 1;
    assert_eq!(verify(RSA, &changed_dg1).state, State::Invalid);
}
#[test]
fn cms_scope_identity_digest_algorithm_and_signature_are_bound() {
    let cases = [
        mutate(RSA, |s| {
            s.encapsulated.content_type = ObjectIdentifier::new_unwrap("1.2.840.113549.1.7.1")
        }),
        mutate(RSA, |s| s.version = 1),
        mutate(RSA, |s| s.certificates = None),
        mutate(RSA, |s| signer(s, |p| p.version = 3)),
        mutate(RSA, |s| {
            signer(s, |p| {
                p.sid = Any::new(
                    Tag::ContextSpecific {
                        constructed: false,
                        number: der::TagNumber(0),
                    },
                    vec![0; 20],
                )
                .unwrap()
            })
        }),
        mutate(RSA, |s| signer(s, |p| p.attributes = None)),
        mutate(RSA, |s| {
            signer(s, |p| p.signature = OctetString::new(vec![0; 256]).unwrap())
        }),
        mutate(RSA, |s| {
            signer(s, |p| {
                p.digest.oid = ObjectIdentifier::new_unwrap("2.16.840.1.101.3.4.2.2")
            })
        }),
        mutate(RSA, |s| {
            signer(s, |p| {
                let mut attrs = p.attributes.take().unwrap().into_vec();
                attrs.retain(|a| !oid(a.oid, "1.2.840.113549.1.9.4"));
                p.attributes = Some(SetOfVec::try_from(attrs).unwrap());
            })
        }),
    ];
    for (i, sod) in cases.iter().enumerate() {
        assert_ne!(verify(sod, DG1).state, State::Consistent, "case {i}");
    }
}
#[test]
fn duplicate_groups_attributes_and_signers_do_not_pass() {
    let cases = [
        mutate(RSA, |s| {
            let mut lds =
                Lds::from_der(s.encapsulated.content.as_ref().unwrap().as_bytes()).unwrap();
            lds.hashes[1].number = 1;
            s.encapsulated.content = Some(OctetString::new(lds.to_der().unwrap()).unwrap());
        }),
        mutate(RSA, |s| {
            signer(s, |p| {
                let mut attrs = p.attributes.take().unwrap().into_vec();
                let mut attr = attrs
                    .iter()
                    .find(|a| oid(a.oid, "1.2.840.113549.1.9.4"))
                    .unwrap()
                    .clone();
                attr.values = SetOfVec::try_from(vec![
                    Any::encode_from(&OctetString::new(vec![0; 32]).unwrap()).unwrap(),
                ])
                .unwrap();
                attrs.push(attr);
                p.attributes = Some(SetOfVec::try_from(attrs).unwrap());
            })
        }),
        mutate(RSA, |s| {
            let p = s.signers.get(0).unwrap().to_der().unwrap();
            let mut extra = Signer::from_der(&p).unwrap();
            extra.version = 3;
            let mut signers = std::mem::take(&mut s.signers).into_vec();
            signers.push(extra);
            s.signers = SetOfVec::try_from(signers).unwrap();
        }),
    ];
    for sod in cases {
        assert_eq!(verify(&sod, DG1).state, State::Invalid);
    }
}
#[test]
fn pss_parameters_cannot_select_an_unbound_mgf_or_salt() {
    let sod = include_bytes!("../fixtures/pss-sha256.sod");
    for variant in 0..4 {
        let changed = mutate(sod, |s| {
            signer(s, |p| {
                let mut params = p
                    .algorithm
                    .parameters
                    .as_ref()
                    .unwrap()
                    .decode_as::<PssParameters>()
                    .unwrap();
                match variant {
                    0 => {
                        params.hash.as_mut().unwrap().oid =
                            ObjectIdentifier::new_unwrap("2.16.840.1.101.3.4.2.2")
                    }
                    1 => params.salt = Some(20),
                    2 => params.trailer = Some(2),
                    _ => {
                        params.mask.as_mut().unwrap().parameters = Some(
                            Any::encode_from(&AlgorithmIdentifier {
                                oid: ObjectIdentifier::new_unwrap("2.16.840.1.101.3.4.2.2"),
                                parameters: None,
                            })
                            .unwrap(),
                        )
                    }
                }
                p.algorithm.parameters = Some(Any::encode_from(&params).unwrap());
            })
        });
        assert_ne!(verify(&changed, DG1).state, State::Consistent);
    }
}
#[test]
fn malformed_noncanonical_trailing_and_oversized_evidence_is_rejected() {
    for data in [
        &[][..],
        &[0x77, 0x80][..],
        &RSA[..RSA.len() - 1],
        &[0x77, 0x82, 0x20, 1][..],
        &vec![0; MAX_SOD + 1][..],
    ] {
        assert_eq!(verify(data, DG1).state, State::Invalid);
    }
    let mut trailing = RSA.to_vec();
    trailing.push(0);
    assert_eq!(verify(&trailing, DG1).state, State::Invalid);
    let unsupported = mutate(RSA, |s| {
        signer(s, |p| {
            p.algorithm.oid = ObjectIdentifier::new_unwrap("1.2.3.4")
        })
    });
    assert_eq!(verify(&unsupported, DG1).state, State::Unsupported);
}
