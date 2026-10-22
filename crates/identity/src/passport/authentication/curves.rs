//! Explicit parameters are accepted only after matching every mathematical field
//! to a supported standard curve. Never infer a curve from point length alone.
use super::*;
use der::asn1::{BitString, Uint};

#[derive(Sequence, PartialEq)]
struct Field {
    kind: ObjectIdentifier,
    prime: Uint,
}
#[derive(Sequence)]
struct Equation {
    a: OctetString,
    b: OctetString,
    seed: Option<BitString>,
}
#[derive(Sequence)]
struct Domain {
    version: u8,
    field: Field,
    equation: Equation,
    base: OctetString,
    order: Uint,
    cofactor: Option<Uint>,
    hash: Option<AlgorithmIdentifier>,
}
pub(super) enum Curve {
    P256,
    P384,
}
pub(super) fn identify(parameters: &Any) -> Result<Curve> {
    if let Ok(named) = parameters.decode_as::<ObjectIdentifier>() {
        return match named.to_string().as_str() {
            "1.2.840.10045.3.1.7" => Ok(Curve::P256),
            "1.3.132.0.34" => Ok(Curve::P384),
            _ => Err(State::Unsupported),
        };
    }
    let bytes = parameters.to_der().map_err(invalid)?;
    ensure(bytes.len() <= 512)?;
    let supplied = Domain::from_der(&bytes).map_err(|_| State::Unsupported)?;
    for (curve, expected) in [
        (
            Curve::P256,
            include_bytes!("../trust/p256-parameters.der").as_slice(),
        ),
        (
            Curve::P384,
            include_bytes!("../trust/p384-parameters.der").as_slice(),
        ),
    ] {
        let standard = Domain::from_der(expected).map_err(invalid)?;
        if supplied.version == 1
            && supplied.field == standard.field
            && supplied.equation.a == standard.equation.a
            && supplied.equation.b == standard.equation.b
            && supplied
                .equation
                .seed
                .as_ref()
                .is_none_or(|s| s.raw_bytes().len() <= 64)
            && supplied.base == standard.base
            && supplied.order == standard.order
            && supplied
                .cofactor
                .as_ref()
                .is_none_or(|n| n.as_bytes() == [1])
            && supplied.hash.is_none()
        {
            return Ok(curve);
        }
    }
    Err(State::Unsupported)
}
