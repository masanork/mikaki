//! Experimental RFC 8628 grant state transitions, not an authorization server.
//!
//! Callers MUST serialize each load/transition/store as one atomic operation;
//! this module provides no persistence, entropy, authentication, rate limiting,
//! token issuance, phishing mitigation or DPoP proof validation. Do not expose
//! this state machine directly as a production endpoint.

/// The client is bound to a prevalidated proof-key thumbprint by a separate,
/// currently unspecified profile. Neither string authenticates a client.
#[derive(Debug, Eq, PartialEq)]
pub struct Grant {
    client: String,
    key_thumbprint: String,
    expires_at: u64,
    interval: u64,
    next_poll_at: u64,
    state: State,
}

#[derive(Clone, Debug, Eq, PartialEq)]
enum State {
    Pending,
    Approved { owner: String },
    Denied,
    Redeemed,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum PollResult {
    AuthorizationPending,
    SlowDown,
    AccessDenied,
    ExpiredToken,
    InvalidGrant,
    /// This is only a state transition, not an issued token.
    Authorized {
        owner: String,
    },
}

impl Grant {
    /// Times are server-side seconds. The caller verifies client policy, the
    /// digest of device_code and the cryptographic proof before transition.
    pub fn new(
        client: String,
        key_thumbprint: String,
        now: u64,
        expires_at: u64,
        interval: u64,
    ) -> Option<Self> {
        if client.is_empty() || key_thumbprint.is_empty() || expires_at <= now || interval == 0 {
            return None;
        }
        Some(Self {
            client,
            key_thumbprint,
            expires_at,
            interval,
            next_poll_at: now.saturating_add(interval),
            state: State::Pending,
        })
    }

    /// Call only after an authenticated, CSRF-protected user decision and any
    /// required phishing/proximity mitigation have succeeded.
    pub fn approve(&mut self, owner: &str, now: u64) -> bool {
        if owner.is_empty() || now >= self.expires_at || self.state != State::Pending {
            return false;
        }
        self.state = State::Approved {
            owner: owner.to_owned(),
        };
        true
    }

    pub fn deny(&mut self, now: u64) -> bool {
        if now >= self.expires_at || self.state != State::Pending {
            return false;
        }
        self.state = State::Denied;
        true
    }

    /// `verified_key` MUST come from successful proof-of-possession validation,
    /// not an unverified request field. Atomic persistence must include any
    /// token issuance or define explicit lost-response recovery.
    pub fn poll(&mut self, client: &str, verified_key: &str, now: u64) -> PollResult {
        if client != self.client || verified_key != self.key_thumbprint {
            return PollResult::InvalidGrant;
        }
        if now >= self.expires_at {
            return PollResult::ExpiredToken;
        }
        if self.state == State::Redeemed {
            return PollResult::InvalidGrant;
        }
        if self.state == State::Denied {
            return PollResult::AccessDenied;
        }
        if now < self.next_poll_at {
            self.interval = self.interval.saturating_add(5);
            self.next_poll_at = now.saturating_add(self.interval);
            return PollResult::SlowDown;
        }
        self.next_poll_at = now.saturating_add(self.interval);
        match &self.state {
            State::Pending => PollResult::AuthorizationPending,
            State::Approved { owner } => {
                let owner = owner.clone();
                self.state = State::Redeemed;
                PollResult::Authorized { owner }
            }
            State::Denied | State::Redeemed => unreachable!(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn grant() -> Grant {
        Grant::new("nihos".into(), "key".into(), 100, 200, 5).unwrap()
    }

    #[test]
    fn pending_slowdown_and_one_time_authorization() {
        let mut g = grant();
        assert_eq!(
            g.poll("nihos", "key", 105),
            PollResult::AuthorizationPending
        );
        assert_eq!(g.poll("nihos", "key", 106), PollResult::SlowDown);
        assert!(g.approve("alice", 107));
        assert_eq!(
            g.poll("nihos", "key", 116),
            PollResult::Authorized {
                owner: "alice".into()
            }
        );
        assert_eq!(g.poll("nihos", "key", 130), PollResult::InvalidGrant);
        assert!(!g.approve("bob", 130));
    }

    #[test]
    fn wrong_client_or_key_cannot_consume_or_change_poll_timing() {
        let mut g = grant();
        assert_eq!(g.poll("other", "key", 101), PollResult::InvalidGrant);
        assert_eq!(g.poll("nihos", "other", 101), PollResult::InvalidGrant);
        assert!(g.approve("alice", 102));
        assert_eq!(
            g.poll("nihos", "key", 105),
            PollResult::Authorized {
                owner: "alice".into()
            }
        );
    }

    #[test]
    fn expiry_denial_and_invalid_construction() {
        let mut expired = grant();
        assert!(!expired.approve("alice", 200));
        assert_eq!(expired.poll("nihos", "key", 200), PollResult::ExpiredToken);
        let mut denied = grant();
        assert!(denied.deny(101));
        assert!(!denied.approve("alice", 102));
        assert_eq!(denied.poll("nihos", "key", 105), PollResult::AccessDenied);
        assert!(Grant::new("nihos".into(), "key".into(), 100, 200, 0).is_none());
    }
}
