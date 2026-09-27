//! A permission: one subject and the Contracts it may present content under.

use authorize::subject::Subject;
use context::AuthenticatedIdentity;

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
                .any(|pattern| authorize::pattern::matches(pattern, contract))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use context::Verified;
    use xcore::{Established, PartyId, mechanism};

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
        let by_value = Permission::new(Subject::identity("ISA06=PARTNERX")).to_present("X12-850");

        assert!(by_party.permits(&isa06(), "X12-850"));
        assert!(by_party.permits(&isa06(), "X12-997"));
        assert!(by_value.permits(&isa06(), "X12-850"));
        assert!(!by_value.permits(&isa06(), "X12-997"));
        assert!(!Permission::new(Subject::Party(PartyId::new(8))).permits(&isa06(), "X12-850"));
    }
}
