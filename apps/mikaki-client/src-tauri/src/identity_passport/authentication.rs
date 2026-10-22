//! Native clock/build configuration adapter. Verification itself is shared with servers.
use mikaki_identity::passport::{self, Evidence, Policy};
pub(crate) use passport::{Report, State};
pub(super) const MAX_SOD: usize = passport::MAX_SOD;
pub(super) fn verify(sod: &[u8], dg1: &[u8]) -> Report {
    let Ok(evidence) = Evidence::from_bytes(dg1.to_vec(), sod.to_vec()) else {
        return Report::new(State::Invalid);
    };
    let policy = match option_env!("MIKAKI_PASSPORT_CRLS") {
        Some(json) => match Policy::from_json(json) {
            Ok(policy) => policy,
            Err(_) => {
                let mut report = Report::new(State::NotChecked);
                report.issuer_trust = "policy_invalid";
                return report;
            }
        },
        None => Policy::default(),
    };
    let Ok(now) = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH) else {
        let mut report = Report::new(State::NotChecked);
        report.issuer_trust = "clock_unavailable";
        return report;
    };
    evidence.inspect(&policy, now.as_secs())
}
