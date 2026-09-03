# BORDINALS protocol sketch

BORDINALS is an implemented, authenticated P2WSH data transport for Bitcoin
Knots with BIP-110/RDTS active. The name combines **BLAKE2b** with **ordinals**:
the application manifest identifies content with BLAKE2b-256.

> [!CAUTION]
> BORDINALS depends on a narrow gap in the audited Knots data-carrier scanner.
> A small policy-only patch can stop default relay without making existing
> transactions invalid under consensus. Do not assign valuable assets to this
> experimental protocol.

BORDINALS v1 is a new wire namespace. It uses manifest magic `BORD` and carrier
tag `BOR1`; old `DSTC`/`DST1` DROPSTITCH data is deliberately not accepted as
BORDINALS.

## Carrier construction

A v1 carrier witnessScript has one exact canonical shape:

```text
<250-byte chunk 0> <250-byte chunk 1> OP_2DROP
<250-byte chunk 2> <250-byte chunk 3> OP_2DROP
<250-byte chunk 4> <250-byte chunk 5> OP_2DROP
<uint32 little-endian local index> <BOR1> OP_2DROP
<33-byte compressed public key> OP_CHECKSIG
```

Every 250-byte chunk uses the minimal `OP_PUSHDATA1 0xfa` encoding. Six chunks
carry exactly 1,500 bytes; only the final carrier is zero-padded. The local
index starts at zero and makes commitments unique even when an image contains
identical 1,500-byte regions. `BOR1` domain-separates the index pair from future
templates. The reveal witness is:

```text
[strict-DER low-S ECDSA signature || 0x21, witnessScript]
```

`0x21` is `SIGHASH_ALL | SIGHASH_UNIFIED`. It commits every signature to all
spent outputs, reveal inputs, sequences, and outputs—including the pointer and
manifest—and opts into Knots' BLAKE2b-fork replay protection. Other sighash
types may satisfy Bitcoin Script but are non-canonical BORDINALS and must be
ignored by indexers.

Execution starts with the signature on the stack. Each content pair and then
the index/tag pair are discarded by `OP_2DROP`; `OP_CHECKSIG` consumes the
signature and public key and leaves one true value. P2WSH's implicit clean-stack
rule is satisfied.

The funding output is native P2WSH:

```text
OP_0 <SHA256(witnessScript)>
```

That SHA-256 is intentional and mandatory: Knots' BLAKE2b fork changes block
proof of work and adds a unified signature hash, but it does not change the
SegWit-v0 P2WSH witness program. The 34-byte output sits at the RDTS
output-script ceiling.

Every carrier comes from one common funding transaction containing exactly one
canonical BORDINALS OP_RETURN manifest. The P2WSH programs commit the padded
chunks, key, and local indices. The funding manifest commits the exact content
length, BLAKE2b-256 digest, MIME type, reveal input range, and intended pointer
vout before reveal. The reveal consumes every temporary carrier into one
ordinary P2TR ownership/pointer output and repeats the manifest byte-for-byte in
one zero-valued OP_RETURN output.

## Why current Knots relays it

At Bitcoin Knots tag `v29.4.1.knots20260508`, commit
`8c85b1585dac23f964e2dd32045624de7f02aa58`, Knots extracts a P2WSH
witnessScript and scans it for known disguised data. The scanner counts
conditional envelopes and literal `<data> OP_DROP`, but not two pushes consumed
by `OP_2DROP`. This template also does not match the specialized five-item
OPNet witness shape, so the scanner reports no nonstandard data-carrier bytes.

The other current limits are satisfied:

- RDTS permits each executed pushed element because 250 is at most 256 bytes.
- The 1,561-byte witnessScript is below the 3,600-byte P2WSH ceiling.
- The sole non-script witness item—the signature—is below 80 bytes.
- A conservatively budgeted 73-byte signature gives a 1,639-byte serialized
  witness, below the default global 1,650-byte ceiling.
- The canonical two-output reveal shape with 221 carrier inputs remains below
  the 400,000-WU standard transaction ceiling.
- The RDTS consensus block-weight ceiling is 800,000 WU, leaving room to mine
  the largest conservatively guaranteed-standard reveal.
- The default token rejection rule did not classify the tested `BORD`
  manifests as a token protocol; the two-node proof exercises this default
  unchanged.

The construction is relay-valid because of current policy, not because
consensus guarantees relay. Adding `OP_2DROP` recognition to the scanner would
close the seam without invalidating blocks.

## Version 1 manifest

All integers are unsigned little-endian. BLAKE2b-256 means sequential, unkeyed
BLAKE2b with no salt or personalization and an output length of exactly 32
bytes. Store the digest bytes in native output order, without reversal. It is
not a truncated 64-byte digest. In Python this is exactly
`hashlib.blake2b(content, digest_size=32).digest()`.

| Offset | Bytes | Field |
|---:|---:|---|
| 0 | 4 | magic `BORD` |
| 4 | 1 | version (`1`) |
| 5 | 1 | flags (`0`, raw content) |
| 6 | 2 | first carrier input index |
| 8 | 2 | carrier input count |
| 10 | 2 | ownership/pointer vout |
| 12 | 4 | exact content byte length |
| 16 | 32 | BLAKE2b-256 of decoded content |
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
8. require strict-DER, low-S signatures ending in unified SIGHASH_ALL (`0x21`);
9. strictly match all six content pushes, the index and `BOR1` pushes, all four
   `OP_2DROP`s, and the final compressed-key `OP_CHECKSIG`;
10. require local carrier indices to be exactly `0..input_count-1`;
11. require every carrier to use the same spend key;
12. concatenate the six chunks from each carrier in input order;
13. truncate to `content_length` and reject non-zero trailing padding;
14. require the decoded BLAKE2b-256 to match the manifest; and
15. require `pointer_vout` to identify the intended spendable ownership output.

`bordinals.py` implements the byte/script rules and requires callers to supply
the funding and reveal manifests independently. Transaction ancestry, output
selection, consensus validation, and actual ECDSA evaluation remain an
indexer's responsibility. It also conservatively rejects a P2WSH hash with
Knots' case-insensitive `stamp:` OLGA marker. If that extraordinarily rare
collision occurs, use a different spend key and rebuild all carriers.

## Capacity

BORDINALS carries 1,500 bytes per input—375 times SEQUIN's four bytes per input.
Two local limits matter:

- A 177-input reveal carries 265,500 bytes and conservatively fits Knots'
  default 300 kB block-template serialization target.
- A 221-input reveal carries 331,500 bytes. Its conservative worst-case weight
  is 399,045 WU even with a maximum-length MIME field, below the 400,000-WU
  relay ceiling. The same conservative sizing model yields 400,848 WU for 222
  inputs, so 222 is not guaranteed
  standard; exact weight varies with DER signature lengths.

The 221-input transaction is larger than the separate default 300 kB template
target, so the proof explicitly includes the already-relayed transaction in a
block to demonstrate consensus acceptance. Actual sizes depend on signature
lengths, MIME length, fees, and transaction shape.

Large fanouts must confirm before reveal. Relaying both together can exceed the
default 101-kvB ancestor-package limit even when each transaction is standard by
itself.

## Verified behavior

The two-node `bordinals_regtest.py` proof uses a valid SVG image and demonstrates:

- carrier funding relay and confirmation under compiled Knots policy defaults;
- an identical canonical manifest anchored once in funding and once in reveal;
- exactly four `OP_2DROP`s, zero `OP_DROP`s, and a terminal `OP_CHECKSIG` in
  every carrier;
- complete signed witnesses below the 1,650-byte default ceiling;
- unified `0x21` signatures and rejection after damaging one;
- default-policy `testmempoolaccept` acceptance and peer relay of the reveal;
- byte-exact reconstruction, BLAKE2b-256 verification, and image MIME handling;
- consumption of all P2WSH carrier UTXOs and absence of OP_RETURN from the UTXO
  set; and
- later relay and confirmation of a spend of the P2TR pointer.

An authenticated `<data> OP_DROP <pubkey> OP_CHECKSIG` control is rejected from
the mempool as `txn-datacarrier-nonstandard` but accepted when directly mined in
an RDTS-active block. This proves the positive result exercises the exact
`OP_2DROP` policy distinction rather than Core policy or disabled standardness.

## Remaining risks

- Adding `OP_2DROP` recognition to Knots' scanner immediately removes default
  relay while leaving the transactions consensus-valid.
- Operators may change `-maxscriptsize`, datacarrier settings, token filters, or
  standardness.
- Knots' default Counterparty filter derives an RC4 key from a transaction
  input, so any single-push OP_RETURN has a theoretical 2^-64 accidental match.
  A transaction builder must preflight both funding and reveal with
  `testmempoolaccept`; on collision, rebuild the funding transaction so it has
  a different txid.
- RDTS is temporary; applications must check activation and expiry at the
  target height.
- Archival reconstruction requires access to historical witness data.
- The manifest defines a pointer but not complete duplicate, conflict, transfer,
  burn, reorg, or marketplace rules. A production indexer specification is
  still required.
- Key management and transaction construction in the functional proof are test
  code, not a production wallet.
