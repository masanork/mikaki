use mikaki_fuzz::{assertion_cases, decode, metadata_cases, registration_cases};
use std::{fs, path::Path};
fn write(target: &str, name: &str, prefix: &[u8], bytes: &[u8], expected: Option<bool>) {
    let directory = Path::new("fuzz/corpus").join(target);
    fs::create_dir_all(&directory).unwrap();
    let data = [prefix, bytes].concat();
    // Replay deterministic seeds before writing them: seed generation itself is a smoke test.
    match target {
        "registration" => {
            let actual = mikaki_fuzz::registration(&data);
            assert_eq!(Some(actual), expected, "{name}");
        }
        "assertion" => {
            assert_eq!(Some(mikaki_fuzz::assertion(&data)), expected, "{name}");
        }
        "metadata" => {
            let actual = mikaki_fuzz::metadata(&data);
            if let Some(expected) = expected {
                assert_eq!(actual, expected, "{name}");
            }
        }
        _ => {
            let _ = mikaki_fuzz::assertion(&data);
        }
    }
    fs::write(directory.join(name), data).unwrap();
}
fn main() {
    for (i, case) in registration_cases().iter().enumerate() {
        for (mode, field) in ["attestation", "client_data"].iter().enumerate() {
            write(
                "registration",
                &format!("{i}-{field}"),
                &[i as u8, mode as u8],
                &decode(&case["response"][field]),
                Some(case["ok"].as_bool().unwrap()),
            );
        }
    }
    for (i, case) in assertion_cases().iter().enumerate() {
        for (mode, field) in [
            "authenticator_data",
            "public_key",
            "signature",
            "client_data",
        ]
        .iter()
        .enumerate()
        {
            let source = if *field == "public_key" {
                &case["stored"]
            } else {
                &case["response"]
            };
            write(
                "assertion",
                &format!("{i}-{field}"),
                &[i as u8, mode as u8],
                &decode(&source[field]),
                Some(case["ok"].as_bool().unwrap()),
            );
        }
    }
    for (i, case) in metadata_cases().iter().enumerate() {
        let jwt = case["input"]["jwt"].as_str().unwrap();
        write(
            "metadata",
            &format!("{i}-jwt"),
            &[i as u8, 0],
            jwt.as_bytes(),
            None,
        );
        for (j, crl) in case["input"]["crls"].as_array().unwrap().iter().enumerate() {
            write(
                "metadata",
                &format!("{i}-crl-{j}"),
                &[i as u8, 1],
                &decode(crl),
                None,
            );
        }
        write(
            "metadata",
            &format!("{i}-header"),
            &[i as u8, 3],
            &decode(&jwt.split('.').next().unwrap().into()),
            None,
        );
        write(
            "metadata",
            &format!("{i}-full-input"),
            &[i as u8, 2],
            &serde_json::to_vec(&case["input"]).unwrap(),
            Some(case["ok"].as_bool().unwrap()),
        );
    }
    for (i, case) in mikaki_fuzz::optional()["registrations"]
        .as_array()
        .unwrap()
        .iter()
        .enumerate()
    {
        use sha2::{Digest, Sha256};
        use x509_cert::der::Decode;
        let object: ciborium::Value =
            ciborium::de::from_reader(decode(&case["response"]["attestation"]).as_slice()).unwrap();
        let field = |v: &ciborium::Value, name: &str| {
            v.as_map()
                .unwrap()
                .iter()
                .find(|(k, _)| k.as_text() == Some(name))
                .map(|(_, v)| v.clone())
        };
        if field(&object, "fmt").unwrap().as_text() != Some("android-key") {
            continue;
        }
        let cert = field(&field(&object, "attStmt").unwrap(), "x5c")
            .unwrap()
            .as_array()
            .unwrap()[0]
            .as_bytes()
            .unwrap()
            .clone();
        let Ok(cert) = x509_cert::Certificate::from_der(&cert) else {
            continue;
        };
        for ext in cert.tbs_certificate().extensions().into_iter().flatten() {
            if ext.extn_id.to_string() == "1.3.6.1.4.1.11129.2.1.17" {
                let hash = Sha256::digest(decode(&case["response"]["client_data"]));
                let data = [hash.as_slice(), ext.extn_value.as_bytes()].concat();
                let _ = mikaki_webauthn::fuzz_android_extension(ext.extn_value.as_bytes(), &hash);
                let dir = Path::new("fuzz/corpus/android");
                fs::create_dir_all(dir).unwrap();
                fs::write(dir.join(format!("{i}-extension")), data).unwrap();
            }
        }
    }
    println!("Replayed and wrote registration, assertion and metadata seeds");
}
