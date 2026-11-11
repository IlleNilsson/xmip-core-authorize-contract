# xmip-core-authorize-contract

Contract authorization: whether this identity may present content under this Contract, from a list of what each Party or identity is permitted and the Party each agreed Contract is agreed with; a message-layer policy. A technology of [xmip-core-authorize](https://github.com/IlleNilsson/xmip-core-authorize).

The identity judged is the one the sender proved: the message identity
where it was proven or vouched for, otherwise the transport identity —
`context`'s `IdentityFacts::subject`, the one rule. A name the content
merely claims, an ISA06, is never the one judged. The authorization gate
asks this policy wherever the attempt names a Contract, whether or not the
content proved an identity of its own. A Contract agreed with a Party
(`Contract::agreed`) is that Party's: content bound to it from an identity
that proved to be another Party, or none, is denied before any permission
is read, here and nowhere else (the owner, 2026-11-10; ADR-0019, amendment
2026-11-11). No node links this policy yet.

## Toolchain

`rust-toolchain.toml` pins the toolchain for the whole estate. Do not change it
here.

## Verification

`cargo test`: nine tests — a Party permitted a Contract presents it; one
not permitted is denied saying what it may present; with no Contract there
is no opinion; a claimed message identity is never judged and the
connection is; a Contract agreed with another Party, or presented by an
identity that proved none, is refused, and through the gate
(`authorize::authorize`) where the content proved no identity at all and
the connection proved another Party; a permission for anyone names only
its Contracts; an identity no permission covers is permitted nothing; a
permission matches its subject and a Contract or its prefix. The included
workflow is manual-only and calls the versioned shared workflow at
`IlleNilsson/.github@v1`.
