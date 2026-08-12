# DROPSTITCH design note

DROPSTITCH is a denser, unimplemented inscription transport discovered while
auditing current Knots BIP-110/RDTS policy. The name is a knitting pun and a
literal description of its script shape.

## Hypothesis

Split content into pushes no larger than 256 bytes, arrange them in pairs, and
discard each pair with `OP_2DROP`. End the script with an authenticated spend
condition such as a public key plus `OP_CHECKSIG`. Keep each complete witness
below the current standard witness-size limit and distribute larger payloads
across multiple ordinary, temporary inputs.

Conceptually:

```text
<chunk-0> <chunk-1> OP_2DROP
<chunk-2> <chunk-3> OP_2DROP
...
<pubkey> OP_CHECKSIG
```

Current Knots code audited for `origin/29.x-knots` recognizes the literal
`OP_DROP` pattern in its datacarrier accounting but does not equivalently count
paired pushes consumed by `OP_2DROP`. That suggests about 1.5 KB of payload per
carefully sized input and roughly hundreds of kilobytes in a max-standard-weight
transaction.

## Why it is not the proof of concept

This construction is a policy seam, not a durable protocol surface. It has not
been implemented or exercised by this repository's two-node test. A small policy
patch that teaches the scanner about `OP_2DROP` could stop relay without changing
consensus. Wallet, fee, script, witness, sigop, and transaction-weight limits all
need exact end-to-end validation.

Any implementation must also avoid prohibited or specially handled structures,
including conditional envelopes, annex tricks, `OP_SUCCESS` paths, oversized
pushes, unauthenticated scripts, and permanent carrier outputs.

## Recommendation

Treat DROPSTITCH as a regression-test candidate and policy research artifact.
Do not mint valuable assets with it. SEQUIN is dramatically less efficient, but
its current-policy argument does not depend on this specific opcode-scanner gap.
