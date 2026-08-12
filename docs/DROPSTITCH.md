# DROPSTITCH protocol sketch

DROPSTITCH is an implemented, authenticated P2WSH data transport for an
RDTS-active Bitcoin Knots chain. The name is both a knitting pun and a literal
description of how the script removes each pair of pushed data chunks.

> [!CAUTION]
> DROPSTITCH depends on a narrow gap in the audited Knots data-carrier scanner.
> A small policy-only patch can stop default relay without making existing
> transactions invalid under consensus. Do not assign valuable assets to this
> experimental v1 protocol.

## Carrier construction

A v1 carrier witnessScript has one exact canonical shape:

```text
<250-byte chunk 0> <250-byte chunk 1> OP_2DROP
<250-byte chunk 2> <250-byte chunk 3> OP_2DROP
<250-byte chunk 4> <250-byte chunk 5> OP_2DROP
<uint32 little-endian local index> <DST1> OP_2DROP
<33-byte compressed public key> OP_CHECKSIG
```

Every 250-byte chunk uses the minimal `OP_PUSHDATA1 0xfa` encoding. Six chunks
carry exactly 1,500 bytes; only the final carrier is zero-padded. The local
index starts at zero and makes commitments unique even when an image contains
identical 1,500-byte regions. `DST1` domain-separates the index pair from future
templates. The reveal witness is:

```text
[low-S ECDSA DER signature || SIGHASH_ALL, witnessScript]
```

Execution starts with the signature on the stack. Each content pair and then the
index/tag pair are discarded by `OP_2DROP`; `OP_CHECKSIG` consumes the signature
and public key and leaves one true value. P2WSH's implicit clean-stack rule is
satisfied. V1 requires strict-DER, low-S signatures with exactly `SIGHASH_ALL`,
so every signature commits to all reveal inputs, sequences, and outputs,
including the pointer and manifest. Other sighash types can satisfy Bitcoin
Script but are non-canonical DROPSTITCH and must be ignored by indexers.

The funding output is native P2WSH:

```text
OP_0 <SHA256(witnessScript)>
```

It is 34 bytes, at the RDTS output-script ceiling. Every carrier must come from
one common funding transaction containing exactly one canonical DROPSTITCH
OP_RETURN manifest. The carrier hashes commit the padded chunks, key, and local
indices; the funding manifest additionally commits their exact length and
SHA-256, MIME type, reveal input range, and intended pointer vout before reveal.
The funding outputs are temporary: the reveal consumes all of them into one
ordinary P2TR ownership/pointer output and repeats the manifest byte-for-byte in
one zero-valued OP_RETURN output.

## Why current Knots relays it

At audited commit `2d531eaf4b0801278b3e928cf9df3b3852001d0a`, Knots extracts the
P2WSH witnessScript and scans for known disguised data. It counts conditional
envelopes and literal `<data> OP_DROP`, but it does not count two pushes consumed
by `OP_2DROP`. This template also does not match the specialized five-item OPNet
witness shape. The scanner therefore reports no nonstandard data-carrier bytes.

The other current limits are satisfied:

- RDTS permits each executed pushed element because 250 is at most 256 bytes.
- The 1,561-byte witnessScript is below the 3,600-byte P2WSH-specific ceiling.
- The sole non-script witness item—the signature—is below 80 bytes.
- A conservatively budgeted 73-byte signature gives a 1,639-byte serialized
  witness, below the default global 1,650-byte ceiling.
- Four `OP_2DROP`s plus one `OP_CHECKSIG` are far below script operation and
  signature-operation limits.

With the required index/tag pair, the mathematical payload ceiling is 1,512
bytes with any standard low-S signature, or 1,513 bytes when low-R signing is
guaranteed. V1 uses six fixed 250-byte chunks instead. Its 1,500-byte capacity
leaves 12 bytes under the standard low-S worst case (11 under the deliberately
conservative 73-byte signature budget) and avoids content-dependent
minimal-push encoding.

## Version 1 manifest

All integers are unsigned little-endian.

| Offset | Bytes | Field |
|---:|---:|---|
| 0 | 4 | magic `DSTC` |
| 4 | 1 | version (`1`) |
| 5 | 1 | flags (`0`, raw content) |
| 6 | 2 | first carrier input index |
| 8 | 2 | carrier input count |
| 10 | 2 | ownership/pointer vout |
| 12 | 4 | exact content byte length |
| 16 | 32 | SHA-256 of decoded content |
| 48 | 1 | MIME byte length |
| 49 | 1..31 | visible ASCII MIME type |

The manifest is at most 80 bytes. Its minimally encoded OP_RETURN script is at
most 83 bytes, matching both the RDTS output limit and the audited default
datacarrier allowance. Exactly the same manifest bytes must appear once in the
common funding transaction and once in the reveal transaction.

## Canonical decoding

A v1 decoder must operate on consensus-validated transactions and:

1. require every selected carrier prevout to come from one common funding
   transaction;
2. require that funding transaction to contain exactly one valid v1 manifest;
3. require the reveal to contain exactly one valid, byte-identical manifest;
4. reject unknown magic, version, flags, or malformed MIME values;
5. require `input_count == ceil(content_length / 1500)`;
6. select the manifest's contiguous reveal-input range and verify those inputs
   spend the common funding transaction's corresponding carrier outputs;
7. require each selected witness to contain exactly the signature and script;
8. require strict-DER, low-S signatures ending in `SIGHASH_ALL` (`0x01`);
9. strictly match all six content pushes, the index and `DST1` pushes, all four
   `OP_2DROP`s, and the final compressed-key `OP_CHECKSIG`;
10. require local carrier indices to be exactly `0..input_count-1`;
11. require every carrier to use the same spend key;
12. concatenate the six chunks from each carrier in input order;
13. truncate to `content_length` and reject non-zero trailing padding;
14. require the decoded SHA-256 to match the manifest; and
15. require `pointer_vout` to identify the intended spendable ownership output.

`dropstitch.py` implements the byte/script rules and requires callers to supply
the funding and reveal manifests independently; transaction ancestry, output
selection, consensus validation, and actual ECDSA evaluation remain an
indexer's responsibility. It also conservatively rejects a P2WSH hash with
Knots' case-insensitive `stamp:` OLGA marker. If that extraordinarily rare
collision occurs, use a different spend key and rebuild all carriers.

## Capacity

The conservative protocol carries 1,500 bytes per input—375 times SEQUIN's four
bytes per input. Two different local limits matter:

- A 177-input reveal carries 265,500 bytes and conservatively fits Knots' default
  300 kB block-template serialization target. The tested transaction was about
  297.2 kB and 319.4 kWU and was selected normally.
- A 220-input reveal carries 330,000 bytes while staying below the 400,000-WU
  standard-transaction ceiling. Repeated test transactions were accepted and
  relayed at roughly 369.4 kB and 396.9 kWU. Knots' default block template left
  them in the mempool because of the separate 300 kB byte target; explicit block
  inclusion then proved consensus validity.

Actual capacity depends on the transaction's other fields, signature sizes,
fees, miner template settings, and node configuration.

Large fanouts must confirm before reveal. Relaying both together can exceed the
default 101-kvB ancestor-package limit even when each transaction is standard by
itself.

## Verified behavior

The two-node `dropstitch_regtest.py` proof uses a valid 5,025-byte SVG image and
demonstrates:

- carrier funding relay and confirmation;
- an identical canonical manifest anchored once in funding and once in reveal;
- exactly four `OP_2DROP`s, zero `OP_DROP`s, and a terminal `OP_CHECKSIG` in
  every carrier;
- complete signed witnesses of at most 1,638 bytes in the tested run;
- rejection after damaging a carrier signature;
- default-policy `testmempoolaccept` acceptance and peer relay of the reveal;
- byte-exact reconstruction, SHA-256 verification, and `image/svg+xml` MIME;
- consumption of all P2WSH carrier UTXOs and absence of OP_RETURN from the UTXO
  set; and
- later relay and confirmation of a spend of the P2TR pointer.

An authenticated `<data> OP_DROP <pubkey> OP_CHECKSIG` control is rejected from
the mempool as `txn-datacarrier-nonstandard` but accepted when directly mined in
an RDTS-active block. This proves that the positive result exercises the exact
`OP_2DROP` policy distinction rather than Core policy or disabled standardness.

## Remaining risks

- Adding `OP_2DROP` recognition to Knots' scanner immediately removes default
  relay while leaving the transactions consensus-valid.
- Operators may change `-maxscriptsize`, datacarrier settings, or standardness.
- RDTS is a temporary deployment; applications must check activation and expiry
  at the target height.
- Archival reconstruction requires access to historical witness data.
- The manifest defines a pointer but not complete duplicate, conflict, transfer,
  burn, reorg, or marketplace rules. A production indexer specification is
  still required.
- Key management and transaction construction in the functional proof are test
  code, not a production wallet.
