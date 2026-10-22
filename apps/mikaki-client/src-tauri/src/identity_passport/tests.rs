use super::*;
use std::collections::VecDeque;

fn hex(s: &str) -> Vec<u8> {
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
        .collect()
}
fn access() -> Access {
    Access::new("L898902C".into(), "1969-08-06".into(), "1994-06-23".into()).unwrap()
}
fn random() -> [u8; 24] {
    hex("781723860C06C2260B795240CB7049B01C19B33E32804F0B")
        .try_into()
        .unwrap()
}
fn session() -> Session {
    Session {
        keys: Keys {
            enc: Zeroizing::new(hex("979EC13B1CBFE9DCD01AB0FED307EAE5").try_into().unwrap()),
            mac: Zeroizing::new(hex("F1CB1F1FB5ADF208806B89DC579DC1F8").try_into().unwrap()),
        },
        ssc: 0x887022120c06c226,
    }
}
struct Script(VecDeque<(Vec<u8>, Vec<u8>)>);
impl CardTransport for Script {
    fn transmit(&mut self, cmd: &[u8]) -> Result<Vec<u8>> {
        let (expected, response) = self
            .0
            .pop_front()
            .expect("no unprotected fallback or extra reads");
        assert_eq!(cmd, expected);
        Ok(response)
    }
}
fn auth_script(response: Vec<u8>) -> Script {
    Script(VecDeque::from([
        (hex("00A4040C07A0000002471001"), hex("9000")),
        (hex("0084000008"), hex("4608F919887022129000")),
        (hex("008200002872C29C2371CC9BDB65B779B8E8D37B29ECC154AA56A8799FAE2F498F76ED92F25F1448EEA8AD90A728"), response),
    ]))
}
fn auth_response() -> Vec<u8> {
    hex("46B9342A41396CD7386BF5803104D7CEDC122B9132139BAF2EEDC94EE178534F2F2D235D074D74499000")
}

#[test]
fn icao_appendix_d_access_keys_and_mutual_authentication_known_answers() {
    let a = access();
    assert_eq!(&*a.info(), b"L898902C<369080619406236");
    let k = Keys::from_mrz(&a.info());
    assert_eq!(&*k.enc, hex("AB94FDECF2674FDFB9B391F85D7F76F2").as_slice());
    assert_eq!(&*k.mac, hex("7962D9ECE03D1ACD4C76089DCE131543").as_slice());
    let mut t = auth_script(auth_response());
    let s = establish(&mut t, &a, &random()).unwrap();
    assert_eq!(&*s.keys.enc, &*session().keys.enc);
    assert_eq!(&*s.keys.mac, &*session().keys.mac);
    assert_eq!(s.ssc, session().ssc);
    assert!(t.0.is_empty());
}
#[test]
fn icao_appendix_d_secure_select_and_read_known_answers() {
    let mut s = session();
    assert_eq!(
        &*s.wrap([0, 0xa4, 2, 0x0c], &[1, 0x1e], None).unwrap(),
        &hex("0CA4020C158709016375432908C044F68E08BF8B92D635FF24F800")
    );
    assert!(s
        .unwrap(&hex("990290008E08FA855A5D4C50A8ED9000"))
        .unwrap()
        .is_empty());
    assert_eq!(
        &*s.wrap([0, 0xb0, 0, 0], &[], Some(4)).unwrap(),
        &hex("0CB000000D9701048E08ED6705417E96BA5500")
    );
    assert_eq!(
        &*s.unwrap(&hex(
            "8709019FF0EC34F9922651990290008E08AD55CC17140B2DED9000"
        ))
        .unwrap(),
        &hex("60145F01")
    );
    assert_eq!(
        &*s.wrap([0, 0xb0, 0, 4], &[], Some(18)).unwrap(),
        &hex("0CB000040D9701128E082EA28A70F3C7B53500")
    );
    assert_eq!(&*s.unwrap(&hex("871901FB9235F4E4037F2327DCC8964F1F9B8C30F42C8E2FFF224A990290008E08C8B2787EAEA07D749000")).unwrap(), &hex("04303130365F36063034303030305C026175"));
}
#[test]
fn authentication_rejects_bad_mac_length_status_and_nonce_without_fallback() {
    let a = access();
    for variant in 0..5 {
        let mut response = auth_response();
        match variant {
            0 => response[32] ^= 1,
            1 => {
                response.remove(0);
            }
            2 => {
                response = hex("6300");
            }
            _ => {
                let k = Keys::from_mrz(&a.info());
                let mut decoded = crypt(&k.enc, &response[..32], false).unwrap();
                decoded[if variant == 3 { 0 } else { 8 }] ^= 1;
                response = crypt(&k.enc, &decoded, true).unwrap().to_vec();
                response.extend_from_slice(&mac(&k.mac, &pad(&response)).unwrap());
                response.extend_from_slice(&[0x90, 0]);
            }
        }
        let mut t = auth_script(response);
        assert_eq!(
            establish(&mut t, &a, &random()).err().unwrap().code,
            FailureCode::PassportAuthenticationFailed
        );
        assert!(t.0.is_empty());
    }
}
#[test]
fn secure_response_rejects_tampering_replay_duplicates_unknown_objects_and_overflow() {
    let good = hex("990290008E08FA855A5D4C50A8ED9000");
    for data in [
        hex("990290008E08FA855A5D4C50A8EC9000"),
        hex("99029000990290008E08FA855A5D4C50A8ED9000"),
        hex("8500990290008E08FA855A5D4C50A8ED9000"),
        hex("99810290008E08FA855A5D4C50A8ED9000"),
        hex("8E08FA855A5D4C50A8ED990290009000"),
        [good[..good.len() - 2].to_vec(), vec![0], vec![0x90, 0]].concat(),
        hex("9000"),
    ] {
        let mut s = session();
        s.ssc += 1;
        assert!(s.unwrap(&data).is_err());
    }
    let mut s = session();
    s.ssc += 1;
    s.unwrap(&good).unwrap();
    assert_eq!(
        s.unwrap(&good).unwrap_err().code,
        FailureCode::PassportIntegrityFailed
    );
    let mut s = session();
    s.ssc = u64::MAX;
    assert!(s.wrap([0, 0xb0, 0, 0], &[], Some(4)).is_err());
    assert!(s.unwrap(&good).is_err());
    let mut long_padding = vec![0x80];
    long_padding.resize(16, 0);
    let s = session();
    assert!(crypto::decrypt_padded(
        &s.keys.enc,
        &crypt(&s.keys.enc, &long_padding, true).unwrap()
    )
    .is_err());
}
fn dg1() -> Vec<u8> {
    let line1 = format!("{:<44}", "P<UTOERIKSSON<<ANNA<MARIA").replace(' ', "<");
    let mut line2 = b"L898902C<3UTO6908061F9406236<<<<<<<<<<<<<<0".to_vec();
    let composite = [&line2[..10], &line2[13..20], &line2[21..43]].concat();
    line2.push(check(&composite));
    assert_eq!(line2.len(), 44);
    [vec![0x61, 91, 0x5f, 0x1f, 88], line1.into_bytes(), line2].concat()
}
fn response(s: &Session, ssc: u64, data: &[u8]) -> Vec<u8> {
    response_status(s, ssc, data, 0x9000)
}
fn response_status(s: &Session, ssc: u64, data: &[u8], status: u16) -> Vec<u8> {
    let mut out = Vec::new();
    if !data.is_empty() {
        let encrypted = crypt(&s.keys.enc, &pad(data), true).unwrap();
        out.push(0x87);
        if encrypted.len() + 1 >= 128 {
            out.push(0x81);
        }
        out.extend_from_slice(&[(encrypted.len() + 1) as u8, 1]);
        out.extend_from_slice(&encrypted);
    }
    out.extend_from_slice(&[0x99, 2]);
    out.extend_from_slice(&status.to_be_bytes());
    let input = [ssc.to_be_bytes().as_slice(), &out].concat();
    out.extend_from_slice(&[0x8e, 8]);
    out.extend_from_slice(&mac(&s.keys.mac, &pad(&input)).unwrap());
    out.extend_from_slice(&[0x90, 0]);
    out
}
#[test]
fn complete_bac_read_returns_only_an_unverified_bounded_dg1_summary() {
    let data = dg1();
    let mut t = auth_script(auth_response());
    let mut s = session();
    for (header, body, le, contents) in [
        ([0, 0xa4, 2, 0x0c], &[1, 1][..], None, &[][..]),
        ([0, 0xb0, 0, 0], &[][..], Some(4), &data[..4]),
        ([0, 0xb0, 0, 4], &[][..], Some(89), &data[4..]),
    ] {
        let cmd = s.wrap(header, body, le).unwrap().to_vec();
        s.ssc += 1;
        t.0.push_back((cmd, response(&s, s.ssc, contents)));
    }
    let cmd = s
        .wrap([0, 0xa4, 2, 0x0c], &[1, 0x1d], None)
        .unwrap()
        .to_vec();
    s.ssc += 1;
    t.0.push_back((cmd, response_status(&s, s.ssc, &[], 0x6a82)));
    let read = read_with_random(&mut t, &access(), &random()).unwrap();
    assert!(read.passport.matches(&read.preview));
    assert_eq!(read.passport.document_number, "L898902C");
    assert_eq!(read.passport.mrz.as_bytes(), &dg1()[5..]);
    let preview = read.preview;
    assert!(t.0.is_empty());
    assert_eq!(preview.document_type, DocumentType::Passport);
    assert_eq!(preview.name, "ERIKSSON ANNA MARIA");
    assert_eq!(preview.birth_date, "1969-08-06");
    assert_eq!(preview.expiry_date.as_deref(), Some("1994-06-23"));
    assert_eq!(preview.verification, "unverified");
    assert!(!preview.backend_verifiable);
    let json = serde_json::to_string(&preview).unwrap();
    for secret in ["L898902C", "KIFD", "MRZ", "239AB9"] {
        assert!(!json.contains(secret));
    }
}
#[test]
fn full_secure_sod_read_and_encrypted_record_payload_recompute_consistency_without_authority() {
    let dg = dg1();
    assert_eq!(
        dg,
        include_bytes!("../../../../../crates/identity/src/passport/fixtures/dg1.bin")
    );
    let sod = include_bytes!("../../../../../crates/identity/src/passport/fixtures/pss-sha256.sod");
    let mut t = auth_script(auth_response());
    let mut s = session();
    for (header, body, le, contents) in [
        ([0, 0xa4, 2, 0x0c], &[1, 1][..], None, &[][..]),
        ([0, 0xb0, 0, 0], &[][..], Some(4), &dg[..4]),
        ([0, 0xb0, 0, 4], &[][..], Some(89), &dg[4..]),
        ([0, 0xa4, 2, 0x0c], &[1, 0x1d][..], None, &[][..]),
        ([0, 0xb0, 0, 0], &[][..], Some(4), &sod[..4]),
    ] {
        let cmd = s.wrap(header, body, le).unwrap().to_vec();
        s.ssc += 1;
        t.0.push_back((cmd, response(&s, s.ssc, contents)));
    }
    let mut offset = 4;
    while offset < sod.len() {
        let count = (sod.len() - offset).min(208);
        let cmd = s
            .wrap(
                [0, 0xb0, (offset >> 8) as u8, offset as u8],
                &[],
                Some(count as u8),
            )
            .unwrap()
            .to_vec();
        s.ssc += 1;
        t.0.push_back((cmd, response(&s, s.ssc, &sod[offset..offset + count])));
        offset += count;
    }
    let read = read_with_random(&mut t, &access(), &random()).unwrap();
    assert!(t.0.is_empty());
    assert!(read.passport.matches(&read.preview));
    let json = serde_json::to_string(&read.passport).unwrap();
    let restored: PassportData = serde_json::from_str(&json).unwrap();
    assert!(restored.matches(&read.preview));
    assert_eq!(
        restored.authentication().state,
        authentication::State::Consistent
    );
    assert_eq!(restored.authentication().issuer_trust, "unknown_issuer");
    assert!(!read.preview.backend_verifiable);
    assert_eq!(read.preview.verification, "unverified");
    let mut invalid = restored;
    let mut bytes = B64.decode(invalid.sod.as_ref().unwrap()).unwrap();
    let last = bytes.len() - 1;
    bytes[last] ^= 1;
    invalid.sod = Some(B64.encode(bytes));
    assert_ne!(
        invalid.authentication().state,
        authentication::State::Consistent
    );
    invalid.sod = Some("!".repeat(10925));
    assert!(!invalid.matches(&read.preview));
}
#[test]
fn missing_sod_status_must_itself_be_authenticated() {
    let mut s = session();
    let cmd = s
        .wrap([0, 0xa4, 2, 0x0c], &[1, 0x1d], None)
        .unwrap()
        .to_vec();
    s.ssc += 1;
    let good = response_status(&s, s.ssc, &[], 0x6a82);
    let mut bad = good.clone();
    let i = bad.len() - 3;
    bad[i] ^= 1;
    let mut t = Script(VecDeque::from([(cmd.clone(), bad)]));
    assert_eq!(
        read_sod(&mut t, &mut session()).err().unwrap().code,
        FailureCode::PassportIntegrityFailed
    );
    let mut t = Script(VecDeque::from([(cmd, good)]));
    assert!(read_sod(&mut t, &mut session()).unwrap().is_none());
}
#[test]
fn dg1_rejects_wrong_check_digits_mismatched_access_and_unbounded_or_non_td3_data() {
    let data = dg1();
    assert!(preview(&data, &access()).is_ok());
    for pos in [0, 1, 4, 5, 49, 58, 67, 69, 75, 91, 92] {
        let mut tampered = data.clone();
        tampered[pos] ^= 1;
        assert!(preview(&tampered, &access()).is_err(), "offset {pos}");
    }
    let wrong = Access::new("L898902C3".into(), "1969-08-06".into(), "1994-06-23".into()).unwrap();
    assert!(preview(&data, &wrong).is_err());
    let wrong = Access::new("L898902C".into(), "1969-08-07".into(), "1994-06-23".into()).unwrap();
    assert!(preview(&data, &wrong).is_err());
    assert!(preview(&[data.clone(), vec![0]].concat(), &access()).is_err());
    for bytes in [
        vec![0x61, 0x80],
        vec![0x61, 0x82, 0x20, 1],
        vec![0x61, 0x81, 91],
    ] {
        let mut pos = 1;
        assert!(length(&bytes, &mut pos).is_err());
    }
}
#[test]
fn access_rejects_invalid_dates_unicode_extended_numbers_and_ambiguous_centuries() {
    for (n, b, e) in [
        ("", "1969-08-06", "1994-06-23"),
        ("L898902C34", "1969-08-06", "1994-06-23"),
        ("l898902c", "1969-08-06", "1994-06-23"),
        ("L898902C<", "1969-08-06", "1994-06-23"),
        ("旅券", "1969-08-06", "1994-06-23"),
        ("L898902C", "690806", "940623"),
        ("L898902C", "1900-02-29", "1994-06-23"),
        ("L898902C", "2000-02-29", "1994-06-23"),
        ("L898902C", "1969-08-06", "1994-13-23"),
        ("L898902C", "1969-08-06", "1994-06-31"),
        ("L898902C", "1969-08-06", "1994-00-23"),
        ("L898902C", "1969-08-06", "1994-06-00"),
    ] {
        assert_eq!(
            Access::new(n.into(), b.into(), e.into())
                .err()
                .unwrap()
                .code,
            FailureCode::InvalidPassportAccess
        );
    }
    assert!(Access::new("AB1234567".into(), "2000-02-29".into(), "2030-01-01".into()).is_ok());
    struct Removed;
    impl CardTransport for Removed {
        fn transmit(&mut self, _: &[u8]) -> Result<Vec<u8>> {
            Err(FailureCode::Cancelled.into())
        }
    }
    assert_eq!(
        read_with_random(&mut Removed, &access(), &random())
            .err()
            .unwrap()
            .code,
        FailureCode::Cancelled
    );
}
