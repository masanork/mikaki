//! Experimental first-party intake grant. The complete holder set is its one-use budget.
use crate::{
    claim_profile::ClaimProfile,
    issuance::{self, PublicJwk},
    mdoc,
};
use serde::{Deserialize, Serialize};

pub const MAX_SIZE: usize = 8;
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Grant {
    pub age_batch_version: u8,
    pub holder_jwks: Vec<PublicJwk>,
    pub credential_configuration_id: String,
    pub claims_json: String,
}
impl Grant {
    pub fn new(
        keys: Vec<PublicJwk>,
        configuration: String,
        profile: &ClaimProfile,
    ) -> Result<Self, &'static str> {
        let grant = Self {
            age_batch_version: 1,
            holder_jwks: keys,
            credential_configuration_id: configuration,
            claims_json: profile.to_json(),
        };
        grant.validate()?;
        Ok(grant)
    }
    pub fn validate(&self) -> Result<ClaimProfile, &'static str> {
        let profile = ClaimProfile::from_json(&self.claims_json)?;
        if self.age_batch_version != 1
            || !profile.is_age_only()
            || !matches!(
                self.credential_configuration_id.as_str(),
                issuance::CONFIGURATION | mdoc::CONFIGURATION
            )
            || !(2..=MAX_SIZE).contains(&self.holder_jwks.len())
        {
            return Err("invalid_age_batch");
        }
        let mut seen = std::collections::HashSet::new();
        for key in &self.holder_jwks {
            key.verifying_key()?;
            if !seen.insert(key.thumbprint()?) {
                return Err("invalid_age_batch");
            }
        }
        Ok(profile)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use p256::ecdsa::SigningKey;
    fn keys(n: usize) -> Vec<PublicJwk> {
        (1..=n)
            .map(|seed| {
                PublicJwk::from_key(
                    SigningKey::from_slice(&[seed as u8; 32])
                        .unwrap()
                        .verifying_key(),
                )
            })
            .collect()
    }
    #[test]
    fn grant_binds_bounded_unique_keys_format_and_age_profile() {
        for n in 2..=MAX_SIZE {
            let grant = Grant::new(
                keys(n),
                issuance::CONFIGURATION.into(),
                &ClaimProfile::age_only(),
            )
            .unwrap();
            let roundtrip: Grant =
                serde_json::from_str(&serde_json::to_string(&grant).unwrap()).unwrap();
            assert_eq!(
                roundtrip.validate().unwrap().to_json(),
                ClaimProfile::age_only().to_json()
            );
        }
        for n in [0, 1, 9] {
            assert!(
                Grant::new(
                    keys(n),
                    issuance::CONFIGURATION.into(),
                    &ClaimProfile::age_only()
                )
                .is_err()
            );
        }
        let key = keys(1)[0].clone();
        assert!(
            Grant::new(
                vec![key.clone(), key],
                mdoc::CONFIGURATION.into(),
                &ClaimProfile::age_only()
            )
            .is_err()
        );
        for profile in [ClaimProfile::default(), ClaimProfile::all()] {
            assert!(Grant::new(keys(2), issuance::CONFIGURATION.into(), &profile).is_err());
        }
        let mut grant = Grant::new(
            keys(2),
            mdoc::CONFIGURATION.into(),
            &ClaimProfile::age_only(),
        )
        .unwrap();
        grant.age_batch_version = 2;
        assert!(grant.validate().is_err());
        grant.age_batch_version = 1;
        grant.credential_configuration_id = "unknown".into();
        assert!(grant.validate().is_err());
    }
}
