use sakimori_jose_custom_probe::{
    verify_es256, verify_es256_claims, verify_es256_jws_native, verify_rs256, verify_rs256_claims,
};
use std::time::Instant;

fn main() {
    let arguments: Vec<String> = std::env::args().collect();
    let valid = match arguments.as_slice() {
        [_, operation, token, jwk] => match operation.as_str() {
            "verify-es256" => verify_es256(token, jwk),
            "verify-rs256" => verify_rs256(token, jwk),
            "verify-es256-jws" => verify_es256_jws_native(token, jwk),
            _ => {
                eprintln!("unsupported operation: {operation}");
                std::process::exit(2);
            }
        },
        [_, operation, token, jwk, issuer, audience] => match operation.as_str() {
            "verify-es256-claims" => verify_es256_claims(token, jwk, issuer, audience),
            "verify-rs256-claims" => verify_rs256_claims(token, jwk, issuer, audience),
            _ => {
                eprintln!("unsupported operation: {operation}");
                std::process::exit(2);
            }
        },
        [_, operation, token, jwk, iterations]
            if operation == "bench-es256" || operation == "bench-rs256" =>
        {
            let iterations: usize = iterations.parse().unwrap_or_else(|_| {
                eprintln!("iterations must be a positive integer");
                std::process::exit(2);
            });
            if iterations == 0 {
                eprintln!("iterations must be a positive integer");
                std::process::exit(2);
            }
            let verify = if operation == "bench-es256" {
                verify_es256
            } else {
                verify_rs256
            };
            let started = Instant::now();
            for _ in 0..iterations {
                if !verify(token, jwk) {
                    eprintln!("benchmark token verification failed");
                    std::process::exit(1);
                }
            }
            println!(
                "{:.1}",
                started.elapsed().as_nanos() as f64 / iterations as f64
            );
            return;
        }
        _ => {
            eprintln!("fixture verify-es256|verify-rs256 TOKEN PUBLIC_JWK_JSON [ISSUER AUDIENCE]");
            std::process::exit(2);
        }
    };
    println!("{valid}");
}
