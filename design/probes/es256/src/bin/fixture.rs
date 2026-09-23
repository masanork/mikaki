use mikaki_es256_probe::{fixture_sign, fixture_verify};

fn main() {
    let arguments: Vec<String> = std::env::args().collect();
    match arguments.as_slice() {
        [_, operation, message] if operation == "sign" => println!("{}", fixture_sign(message)),
        [_, operation, message, signature] if operation == "verify" => {
            println!("{}", fixture_verify(message, signature));
        }
        _ => {
            eprintln!("fixture sign INPUT | fixture verify INPUT SIGNATURE");
            std::process::exit(2);
        }
    }
}
