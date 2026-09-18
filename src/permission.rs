//! A permission: one subject and the Contracts it may present content under.

use context::AuthenticatedIdentity;
use std::fmt;
use xcore::PartyId;

/// Whom a permission is for.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Subject {
    /// Every identity, resolved to a Party or not.
    Any,
    /// The identity whose presented value is exactly this — `ISA06=PARTNERX`.
    Identity(String),
    /// Whatever identity resolved to this Party. A Party is a shortcut to an
    /// identity, not a permission (ADR-0019 clause 4), so a partner known by
    /// an ISA06 on one Path and a UNB on another is permitted once.
    Party(PartyId),
}

impl Subject {
    #[must_use]
    pub fn matches(&self, identity: &AuthenticatedIdentity) -> bool {
        match self {
            Self::Any => true,
            Self::Identity(value) => identity.value == *value,
            Self::Party(party) => identity.party_id == Some(*party),
        }
    }
}

impl fmt::Display for Subject {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Any => f.write_str("anyone"),
            Self::Identity(value) => write!(f, "'{value}'"),
            Self::Party(party) => write!(f, "party {party}"),
        }
    }
}

/// The Contracts one subject may present content under.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Permission {
    pub subject: Subject,
    /// Contract names, each a name or every name under a prefix when it ends
    /// in `*` — `X12-850`, `X12-*`.
    pub contracts: Vec<String>,
}

impl Permission {
    #[must_use]
    pub fn new(subject: Subject) -> Self {
        Self {
            subject,
            contracts: Vec::new(),
        }
    }

    #[must_use]
    pub fn to_present(mut self, contract: impl Into<String>) -> Self {
        self.contracts.push(contract.into());
        self
    }

    /// Whether this permission lets this identity present this Contract.
    #[must_use]
    pub fn permits(&self, identity: &AuthenticatedIdentity, contract: &str) -> bool {
        self.subject.matches(identity)
            && self
                .contracts
                .iter()
                .any(|pattern| prefix_matches(pattern, contract))
    }
}

/// A name, or every name under a prefix when the pattern ends in `*`.
fn prefix_matches(pattern: &str, name: &str) -> bool {
    match pattern.strip_suffix('*') {
        Some(prefix) => name.starts_with(prefix),
        None => pattern == name,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use context::Verified;
    use xcore::{Established, mechanism};

    fn isa06() -> AuthenticatedIdentity {
        AuthenticatedIdentity::new(
            mechanism::edi_x12_interchange(),
            "ISA06=PARTNERX",
            Established::Detected,
            Verified::Claimed,
        )
        .resolving_to(PartyId::new(7))
    }

    #[test]
    fn a_permission_matches_its_subject_and_a_contract_or_a_prefix_of_one() {
        let by_party = Permission::new(Subject::Party(PartyId::new(7))).to_present("X12-*");
        let by_value =
            Permission::new(Subject::Identity("ISA06=PARTNERX".into())).to_present("X12-850");

        assert!(by_party.permits(&isa06(), "X12-850"));
        assert!(by_party.permits(&isa06(), "X12-997"));
        assert!(by_value.permits(&isa06(), "X12-850"));
        assert!(!by_value.permits(&isa06(), "X12-997"));
        assert!(!Permission::new(Subject::Party(PartyId::new(8))).permits(&isa06(), "X12-850"));
    }

    #[test]
    fn a_subject_reads_as_who_it_is() {
        assert_eq!(Subject::Any.to_string(), "anyone");
        assert_eq!(Subject::Identity("a".into()).to_string(), "'a'");
        assert_eq!(
            Subject::Party(PartyId::new(1)).to_string(),
            "party 00000000-0000-0000-0000-000000000001"
        );
    }
}
