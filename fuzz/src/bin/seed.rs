use mikaki_fuzz::{assertion_seed, decode, fixtures};
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
        "assertion" => mikaki_fuzz::assertion(&data),
        "metadata" => {
            let actual = mikaki_fuzz::metadata(&data);
            if let Some(expected) = expected {
                assert_eq!(actual, expected, "{name}");
            }
        }
        _ => mikaki_fuzz::assertion(&data),
    }
    fs::write(directory.join(name), data).unwrap();
}
fn main() {
    for (i, case) in fixtures()["registrations"]
        .as_array()
        .unwrap()
        .iter()
        .enumerate()
    {
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
    for (mode, field) in [
        "authenticator_data",
        "public_key",
        "signature",
        "client_data",
    ]
    .iter()
    .enumerate()
    {
        write(
            "assertion",
            field,
            &[mode as u8],
            &decode(&assertion_seed()[field]),
            None,
        );
    }
    for (i, case) in fixtures()["mds"].as_array().unwrap().iter().enumerate() {
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
    println!("Replayed and wrote registration, assertion and metadata seeds");
}
