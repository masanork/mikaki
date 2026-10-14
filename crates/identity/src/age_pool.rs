//! Explicit age-only receive budgets, frozen in authenticated PAR.
use crate::{claim_profile::ClaimProfile, issuance::PublicJwk};
use serde::{Deserialize, Serialize};

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Mode {
    #[default]
    Sequential,
    Batch,
}
impl Mode {
    fn sequential(&self) -> bool {
        *self == Self::Sequential
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Budget {
    pub size: usize,
    pub claims_json: String,
    #[serde(default, skip_serializing_if = "Mode::sequential")]
    pub mode: Mode,
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
            age_pool_version: if budget.mode == Mode::Batch { 2 } else { 1 },
            budget,
            holders: Vec::new(),
        })
    }
    pub fn validate(&self, issued: usize) -> Result<(), &'static str> {
        self.budget.validate()?;
        let valid_count = match self.budget.mode {
            Mode::Sequential => {
                self.age_pool_version == 1
                    && self.holders.len() == issued
                    && issued <= self.budget.size
            }
            // The immutable database counter counts endpoint operations. One
            // batch operation atomically records every approved holder.
            Mode::Batch => {
                self.age_pool_version == 2
                    && match issued {
                        0 => self.holders.is_empty(),
                        1 => self.holders.len() == self.budget.size,
                        _ => false,
                    }
            }
        };
        if !valid_count
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
        if self.budget.mode != Mode::Sequential {
            return Err("invalid_age_pool");
        }
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
    pub fn batch(&self, holders: &[PublicJwk]) -> Result<Self, &'static str> {
        self.validate(0)?;
        if self.budget.mode != Mode::Batch || holders.len() != self.budget.size {
            return Err("invalid_age_pool");
        }
        let mut next = self.clone();
        next.holders = holders
            .iter()
            .map(PublicJwk::thumbprint)
            .collect::<Result<_, _>>()?;
        next.validate(1)?;
        Ok(next)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use p256::ecdsa::SigningKey;
    #[test]
    fn batch_state_records_all_holders_in_one_operation_and_rejects_partial_or_duplicate_keys() {
        let budget = Budget {
            size: 8,
            claims_json: ClaimProfile::age_only().to_json(),
            mode: Mode::Batch,
        };
        let state = State::new(budget).unwrap();
        let holders: Vec<_> = (1..=8)
            .map(|n| PublicJwk::from_key(SigningKey::from_slice(&[n; 32]).unwrap().verifying_key()))
            .collect();
        assert!(state.next(&holders[0]).is_err());
        assert!(state.batch(&holders[..7]).is_err());
        let mut duplicate = holders.clone();
        duplicate[7] = holders[0].clone();
        assert!(state.batch(&duplicate).is_err());
        let next = state.batch(&holders).unwrap();
        next.validate(1).unwrap();
        assert!(next.validate(0).is_err());
        assert!(next.validate(8).is_err());
        assert!(next.batch(&holders).is_err());
        let mut downgraded = next;
        downgraded.age_pool_version = 1;
        assert!(downgraded.validate(1).is_err());
    }
    #[test]
    fn budget_and_state_bound_unique_holders_to_an_exact_age_only_count() {
        let budget = Budget {
            size: 8,
            claims_json: ClaimProfile::age_only().to_json(),
            mode: Mode::Sequential,
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
        for raw in [
            r#"{"size":2,"claims_json":"[\"age_over_18\"]","mode":"unknown"}"#,
            r#"{"size":2,"claims_json":"[\"age_over_18\"]","mode":"batch","mode":"sequential"}"#,
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
