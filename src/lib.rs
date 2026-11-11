#![forbid(unsafe_code)]

//! Contract authorization — a technology of `xmip-core-authorize`.
//!
//! One policy: whether this identity may present content under this
//! Contract. A Contract is the shape the content claims to have — an X12 850,
//! an EDIFACT ORDERS, an HL7 ADT, a JSON Schema — and a Party permitted to
//! send invoices is not thereby permitted to send purchase orders. The
//! Attempt carries the Contract where one has been identified; a
//! [`Permission`] says which Contracts one subject may present.
//!
//! **The identity judged is the one the sender proved** (the owner,
//! 2026-11-10: a Party only from what the sender proved): the message
//! identity, the one on whose behalf the content was produced, where it was
//! proven or vouched for, and otherwise the transport identity, who opened
//! the connection — `context`'s `IdentityFacts::subject`, the one rule. A
//! name the content merely claims — an ISA06 — is never the one judged.
//! The gate asks this policy wherever the Attempt names a Contract, a
//! message identity or none. Where the Attempt names no Contract there is nothing to
//! judge and the policy has no opinion — `None` — a raw CSV is some other
//! policy's business. Where it names one, the list is closed: an identity no
//! permission covers is denied, and the denial says what it is permitted,
//! so the operator can see whether the list or the content is wrong.
//!
//! **A Contract agreed with a Party is that Party's** ([`Contract::agreed`]).
//! Content bound to it says, by its binding, who it is from; that is a claim,
//! and it is compared here, once, with the Party the judged identity
//! resolved to: another Party, or none, is denied before any permission is
//! read (ADR-0019, amendment 2026-11-11). `identify/contract` presents no
//! Party for it.
//!
//! Message layer (ADR-0050 section 5). Which connection carried it is the
//! transport layer's question and another policy's.

pub mod permission;

use authorize::{Attempt, Authorizer, Decision};
use context::IdentityFacts;
pub use permission::Permission;
use xcore::{Layer, PartyId};

/// The manifest leaf, and what a denial says it was denied by.
pub const NAME: &str = "contract";

/// The permissions, and the Party each agreed Contract is agreed with. Any
/// one permission permitting the identity for the Contract is enough.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct Contract {
    permissions: Vec<Permission>,
    /// A Contract name, or every name under a prefix ending in `*`, and the
    /// Party it is agreed with.
    agreements: Vec<(String, PartyId)>,
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

    /// `contract` — a name, or every name under a prefix ending in `*` —
    /// agreed with `party`: content bound to it is presented by an identity
    /// that proved to be that Party, or it is denied.
    #[must_use]
    pub fn agreed(mut self, contract: impl Into<String>, party: PartyId) -> Self {
        self.agreements.push((contract.into(), party));
        self
    }

    /// The Party `contract` is agreed with, where an agreement names it.
    #[must_use]
    pub fn agreed_with(&self, contract: &str) -> Option<PartyId> {
        self.agreements
            .iter()
            .find(|(pattern, _)| authorize::pattern::matches(pattern, contract))
            .map(|(_, party)| *party)
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
        // The identity the sender proved: context's one rule for whom the
        // Message is for, never a message identity merely claimed.
        let who = identity.subject();

        if let Some(agreed) = self.agreed_with(contract)
            && who.party_id != Some(agreed)
        {
            let proved = who
                .party_id
                .map_or_else(|| "no Party".to_string(), |party| format!("Party {party}"));
            return Some(Decision::denied(
                NAME,
                format!(
                    "'{contract}' is agreed with Party {agreed}, and '{}' proved to be {proved}",
                    who.value
                ),
            ));
        }

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
    use authorize::subject::Subject;
    use context::{Alignment, AuthenticatedIdentity, Minimum, OnMisalignment, Verified};
    use xcore::{Established, mechanism};

    /// The connection: a VAN's certificate, proven, the VAN's own Party.
    fn van() -> AuthenticatedIdentity {
        AuthenticatedIdentity::new(
            mechanism::mutual_tls(),
            "CN=van.example",
            Established::Passed,
            Verified::Proven,
        )
        .resolving_to(PartyId::new(1))
    }

    /// An interchange sender as `verified` concluded it, resolved to `party`.
    fn isa06(value: &str, verified: Verified, party: Option<PartyId>) -> IdentityFacts {
        let identity = AuthenticatedIdentity::new(
            mechanism::edi_x12_interchange(),
            value,
            Established::Detected,
            verified,
        );
        let identity = match party {
            Some(party_id) => identity.resolving_to(party_id),
            None => identity,
        };

        IdentityFacts::evaluate(Alignment::None, van(), Some(identity))
    }

    /// A sender a broker Xmip proved vouched for.
    fn vouched(value: &str, party: Option<PartyId>) -> IdentityFacts {
        isa06(value, Verified::Vouched, party)
    }

    fn orders() -> Contract {
        Contract::new()
            .permitting(Permission::new(Subject::Party(PartyId::new(7))).to_present("X12-850"))
            .permitting(Permission::new(Subject::Anyone).to_present("X12-997"))
    }

    fn presenting(contract: &str) -> Attempt {
        Attempt::now(Action::Receive, "van-inbound").on_contract(contract)
    }

    #[test]
    fn a_party_permitted_the_contract_may_present_it() {
        let decision = orders().decide(
            &vouched("ISA06=PARTYX", Some(PartyId::new(7))),
            &presenting("X12-850"),
        );

        assert_eq!(decision, Some(Decision::Allowed));
    }

    #[test]
    fn a_contract_the_party_is_not_permitted_is_denied_by_contract_saying_what_it_may() {
        let decision = orders().decide(
            &vouched("ISA06=PARTYX", Some(PartyId::new(7))),
            &presenting("X12-810"),
        );

        assert_eq!(
            decision.map(|decision| decision.to_string()),
            Some(
                "denied by contract: 'ISA06=PARTYX' may not present 'X12-810'; it may \
                 present X12-850, X12-997"
                    .to_string()
            )
        );
    }

    #[test]
    fn with_no_contract_identified_there_is_nothing_to_judge() {
        let decision = orders().decide(
            &vouched("ISA06=PARTYX", Some(PartyId::new(7))),
            &Attempt::now(Action::Receive, "van-inbound"),
        );

        assert_eq!(decision, None);
    }

    #[test]
    fn a_claimed_message_identity_is_never_judged_and_the_connection_is() {
        // The content wrote PARTYX, and nothing proved it: the identity
        // judged is the VAN that proved itself, with a message identity
        // claimed as with none at all.
        let claimed = isa06("ISA06=PARTYX", Verified::Claimed, Some(PartyId::new(7)));
        let without = IdentityFacts::evaluate(Alignment::None, van(), None);
        let judged = Some(Decision::denied(
            NAME,
            "'CN=van.example' may not present 'X12-850'; it may present X12-997",
        ));

        assert_eq!(orders().decide(&claimed, &presenting("X12-850")), judged);
        assert_eq!(orders().decide(&without, &presenting("X12-850")), judged);
        assert_eq!(Contract::new().layer(), Layer::Message);
        assert_eq!(Contract::new().name(), "contract");
    }

    #[test]
    fn a_contract_agreed_with_another_party_is_refused() {
        // The binding says who the content is from; that is a claim, and
        // it is compared with the Party the sender proved, here and once.
        let agreed = Contract::new()
            .agreed("X12-*", PartyId::new(7))
            .permitting(Permission::new(Subject::Anyone).to_present("X12-*"));
        let refused = |by: &str, proved: &str| {
            Some(Decision::denied(
                NAME,
                format!(
                    "'X12-850' is agreed with Party {}, and '{by}' proved to be {proved}",
                    PartyId::new(7)
                ),
            ))
        };

        assert_eq!(
            agreed.decide(
                &vouched("ISA06=PARTYX", Some(PartyId::new(7))),
                &presenting("X12-850")
            ),
            Some(Decision::Allowed)
        );
        assert_eq!(
            agreed.decide(
                &vouched("ISA06=PARTYY", Some(PartyId::new(8))),
                &presenting("X12-850")
            ),
            refused("ISA06=PARTYY", &format!("Party {}", PartyId::new(8)))
        );
        assert_eq!(
            agreed.decide(&vouched("ISA06=PARTYZ", None), &presenting("X12-850")),
            refused("ISA06=PARTYZ", "no Party")
        );
        let claimed = isa06("ISA06=PARTYX", Verified::Claimed, Some(PartyId::new(7)));
        assert_eq!(
            agreed.decide(&claimed, &presenting("X12-850")),
            refused("CN=van.example", &format!("Party {}", PartyId::new(1))),
            "the name the content wrote is not what the sender proved"
        );
        assert_eq!(agreed.agreed_with("EDIFACT-ORDERS"), None);
    }

    /// A transport-layer policy that lets every connection post.
    struct Open;

    impl Authorizer for Open {
        fn name(&self) -> &'static str {
            "open"
        }

        fn layer(&self) -> Layer {
            Layer::Transport
        }

        fn decide(&self, _identity: &IdentityFacts, _attempt: &Attempt) -> Option<Decision> {
            Some(Decision::Allowed)
        }
    }

    #[test]
    fn the_gate_refuses_a_contract_agreed_with_another_party_with_no_message_identity() {
        // Party 8 proved itself over mutual TLS, and its content proved no
        // identity of its own: the gate still asks this policy, which judges
        // the connection and refuses content agreed with Party 7.
        let agreed = Contract::new()
            .agreed("X12-850", PartyId::new(7))
            .permitting(Permission::new(Subject::Anyone).to_present("X12-*"));
        let party_y = AuthenticatedIdentity::new(
            mechanism::mutual_tls(),
            "CN=party-y.example",
            Established::Passed,
            Verified::Proven,
        )
        .resolving_to(PartyId::new(8));
        let facts = IdentityFacts::evaluate(Alignment::None, party_y, None);
        let policies: [&dyn Authorizer; 2] = [&Open, &agreed];

        let decision = authorize::authorize(
            &policies,
            &facts,
            &presenting("X12-850"),
            OnMisalignment::Accept,
            Minimum::TAKEN,
        );

        assert_eq!(
            decision,
            Decision::denied(
                NAME,
                format!(
                    "'X12-850' is agreed with Party {}, and 'CN=party-y.example' proved to be \
                     Party {}",
                    PartyId::new(7),
                    PartyId::new(8)
                ),
            )
        );
    }

    #[test]
    fn a_permission_for_anyone_still_names_only_its_contracts() {
        // Unresolved and unknown: nobody permitted it an 850, and everyone is
        // permitted a 997.
        let stranger = vouched("ISA06=STRANGER", None);

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
            closed.decide(&vouched("ISA06=STRANGER", None), &presenting("X12-850")),
            Some(Decision::denied(
                NAME,
                "'ISA06=STRANGER' is permitted no contract"
            ))
        );
    }
}
