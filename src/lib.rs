#![forbid(unsafe_code)]

//! Contract authorization — a technology of `xmip-core-authorize`.
//!
//! One policy: whether this identity may present content under this
//! Contract. A Contract is the shape the content claims to have — an X12 850,
//! an EDIFACT ORDERS, an HL7 ADT, a JSON Schema — and a partner permitted to
//! send invoices is not thereby permitted to send purchase orders. The
//! Attempt carries the Contract where one has been identified; a
//! [`Permission`] says which Contracts one subject may present.
//!
//! This is the policy that answers ADR-0019's question of the message layer:
//! may a Party recognized only by an ISA06 send this contract on this Path.
//! The identity judged is the message identity, the one on whose behalf the
//! content was produced, and the capability consults this policy only where
//! one exists. Where the Attempt names no Contract there is nothing to judge
//! and the policy has no opinion — `None` — a raw CSV is some other policy's
//! business. Where it names one, the list is closed: an identity no
//! permission covers is denied, and the denial says what it is permitted,
//! so the operator can see whether the list or the content is wrong.
//!
//! Message layer (ADR-0050 section 5). Which connection carried it is the
//! transport layer's question and another policy's.

pub mod permission;

use authorize::{Attempt, Authorizer, Decision};
use context::IdentityFacts;
pub use permission::{Permission, Subject};
use xcore::Layer;

/// The manifest leaf, and what a denial says it was denied by.
pub const NAME: &str = "contract";

/// The permissions. Any one permitting the identity for the Contract is
/// enough.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct Contract {
    permissions: Vec<Permission>,
}

impl Contract {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    #[must_use]
    pub fn permitting(mut self, permission: Permission) -> Self {
        self.permissions.push(permission);
        self
    }

    #[must_use]
    pub fn permissions(&self) -> &[Permission] {
        &self.permissions
    }
}

impl Authorizer for Contract {
    fn name(&self) -> &str {
        NAME
    }

    fn layer(&self) -> Layer {
        Layer::Message
    }

    fn decide(&self, identity: &IdentityFacts, attempt: &Attempt) -> Option<Decision> {
        let contract = attempt.contract.as_deref()?;
        let who = identity.message.as_ref()?;

        if self
            .permissions
            .iter()
            .any(|permission| permission.permits(who, contract))
        {
            return Some(Decision::Allowed);
        }

        let permitted: Vec<&str> = self
            .permissions
            .iter()
            .filter(|permission| permission.subject.matches(who))
            .flat_map(|permission| permission.contracts.iter().map(String::as_str))
            .collect();

        let reason = if permitted.is_empty() {
            format!("'{}' is permitted no contract", who.value)
        } else {
            format!(
                "'{}' may not present '{contract}'; it may present {}",
                who.value,
                permitted.join(", ")
            )
        };

        Some(Decision::denied(NAME, reason))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use authorize::Action;
    use context::{Alignment, AuthenticatedIdentity, Verified};
    use xcore::{Established, PartyId, mechanism};

    fn van() -> AuthenticatedIdentity {
        AuthenticatedIdentity::new(
            mechanism::mutual_tls(),
            "CN=van.example",
            Established::Passed,
            Verified::Proven,
        )
        .resolving_to(PartyId::new(1))
    }

    fn isa06(value: &str, party: Option<PartyId>) -> IdentityFacts {
        let identity = AuthenticatedIdentity::new(
            mechanism::edi_x12_interchange(),
            value,
            Established::Detected,
            Verified::Claimed,
        );
        let identity = match party {
            Some(party_id) => identity.resolving_to(party_id),
            None => identity,
        };

        IdentityFacts::evaluate(Alignment::None, van(), Some(identity))
    }

    fn orders() -> Contract {
        Contract::new()
            .permitting(Permission::new(Subject::Party(PartyId::new(7))).to_present("X12-850"))
            .permitting(Permission::new(Subject::Any).to_present("X12-997"))
    }

    fn presenting(contract: &str) -> Attempt {
        Attempt::new(Action::Receive, "van-inbound").on_contract(contract)
    }

    #[test]
    fn a_party_permitted_the_contract_may_present_it() {
        let decision = orders().decide(
            &isa06("ISA06=PARTNERX", Some(PartyId::new(7))),
            &presenting("X12-850"),
        );

        assert_eq!(decision, Some(Decision::Allowed));
    }

    #[test]
    fn a_contract_the_party_is_not_permitted_is_denied_by_contract_saying_what_it_may() {
        let decision = orders().decide(
            &isa06("ISA06=PARTNERX", Some(PartyId::new(7))),
            &presenting("X12-810"),
        );

        assert_eq!(
            decision.map(|decision| decision.to_string()),
            Some(
                "denied by contract: 'ISA06=PARTNERX' may not present 'X12-810'; it may \
                 present X12-850, X12-997"
                    .to_string()
            )
        );
    }

    #[test]
    fn with_no_contract_identified_there_is_nothing_to_judge() {
        let decision = orders().decide(
            &isa06("ISA06=PARTNERX", Some(PartyId::new(7))),
            &Attempt::new(Action::Receive, "van-inbound"),
        );

        assert_eq!(decision, None);
    }

    #[test]
    fn with_no_message_identity_the_policy_has_no_opinion() {
        // The capability never consults a message-layer policy without one;
        // asked directly, the answer is the same.
        let facts = IdentityFacts::evaluate(Alignment::None, van(), None);

        assert_eq!(orders().decide(&facts, &presenting("X12-850")), None);
        assert_eq!(Contract::new().layer(), Layer::Message);
        assert_eq!(Contract::new().name(), "contract");
    }

    #[test]
    fn a_permission_for_anyone_still_names_only_its_contracts() {
        // Unresolved and unknown: nobody permitted it an 850, and everyone is
        // permitted a 997.
        let stranger = isa06("ISA06=STRANGER", None);

        assert_eq!(
            orders().decide(&stranger, &presenting("X12-997")),
            Some(Decision::Allowed)
        );
        assert_eq!(
            orders().decide(&stranger, &presenting("X12-850")),
            Some(Decision::denied(
                NAME,
                "'ISA06=STRANGER' may not present 'X12-850'; it may present X12-997"
            ))
        );
    }

    #[test]
    fn an_identity_the_list_does_not_know_is_permitted_nothing() {
        let closed = Contract::new()
            .permitting(Permission::new(Subject::Party(PartyId::new(7))).to_present("X12-850"));

        assert_eq!(
            closed.decide(&isa06("ISA06=STRANGER", None), &presenting("X12-850")),
            Some(Decision::denied(
                NAME,
                "'ISA06=STRANGER' is permitted no contract"
            ))
        );
    }
}
