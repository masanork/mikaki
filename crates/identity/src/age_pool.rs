//! Explicit age-only receive budget for sequential HAIP issuance. Not a wire batch.
use crate::{claim_profile::ClaimProfile, issuance::PublicJwk};
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Budget {
    pub size: usize,
    pub claims_json: String,
}
impl Budget {
    pub fn validate(&self) -> Result<ClaimProfile, &'static str> {
        let profile = ClaimProfile::from_json(&self.claims_json)?;
        if !(2..=crate::age_batch::MAX_SIZE).contains(&self.size)
            || !profile.is_age_only()
            || profile.to_json() != self.claims_json
        {
            return Err("invalid_age_pool");
        }
        Ok(profile)
    }
    pub fn parse(raw: &str) -> Result<Self, &'static str> {
        if raw.len() > 1024 {
            return Err("invalid_age_pool");
        }
        let value =
            crate::wallet_profile::strict_json(raw.as_bytes()).map_err(|_| "invalid_age_pool")?;
        let budget: Self = serde_json::from_value(value).map_err(|_| "invalid_age_pool")?;
        budget.validate()?;
        Ok(budget)
    }
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct State {
    pub age_pool_version: u8,
    pub budget: Budget,
    pub holders: Vec<String>,
}
impl State {
    pub fn new(budget: Budget) -> Result<Self, &'static str> {
        budget.validate()?;
        Ok(Self {
            age_pool_version: 1,
            budget,
            holders: Vec::new(),
        })
    }
    pub fn validate(&self, issued: usize) -> Result<(), &'static str> {
        self.budget.validate()?;
        if self.age_pool_version != 1
            || self.holders.len() != issued
            || issued > self.budget.size
            || self.holders.iter().enumerate().any(|(i, h)| {
                h.len() != 43
                    || !h
                        .bytes()
                        .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_'))
                    || self.holders[..i].contains(h)
            })
        {
            return Err("invalid_age_pool");
        }
        Ok(())
    }
    pub fn next(&self, holder: &PublicJwk) -> Result<Self, &'static str> {
        self.validate(self.holders.len())?;
        if self.holders.len() >= self.budget.size {
            return Err("issuance_consumed");
        }
        let thumbprint = holder.thumbprint()?;
        if self.holders.contains(&thumbprint) {
            return Err("invalid_proof");
        }
        let mut next = self.clone();
        next.holders.push(thumbprint);
        Ok(next)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use p256::ecdsa::SigningKey;
    #[test]
    fn budget_and_state_bound_unique_holders_to_an_exact_age_only_count() {
        let budget = Budget {
            size: 8,
            claims_json: ClaimProfile::age_only().to_json(),
        };
        let mut state = State::new(budget.clone()).unwrap();
        for i in 1..=8 {
            let holder =
                PublicJwk::from_key(SigningKey::from_slice(&[i; 32]).unwrap().verifying_key());
            state = state.next(&holder).unwrap();
            state.validate(i as usize).unwrap();
            assert!(state.next(&holder).is_err());
        }
        assert!(state.validate(7).is_err());
        for raw in [
            r#"{"size":2,"size":8,"claims_json":"[\"age_over_18\"]"}"#,
            r#"{"size":9,"claims_json":"[\"age_over_18\"]"}"#,
            r#"{"size":2,"claims_json":"[\"birthdate\"]"}"#,
            r#"{"size":2,"claims_json":"[ \"age_over_18\" ]"}"#,
        ] {
            assert!(Budget::parse(raw).is_err());
        }
        assert_eq!(
            Budget::parse(&serde_json::to_string(&budget).unwrap())
                .unwrap()
                .size,
            8
        );
    }
}
