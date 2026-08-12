# SEQUIN protocol sketch

SEQUIN means **SEQU**ence **IN**scription. Version 1 is a deliberately small,
canonical transport intended for experimentation on an RDTS-active Bitcoin
Knots chain.

The codec treats content as opaque bytes, so images work without a special
format. In practice its four-bytes-per-input density makes tiny SVGs, pixel art,
thumbnails, or hashes more realistic than ordinary PNG/JPEG photographs.

## Transaction shape

The reveal transaction must use transaction version 1 and `nLockTime=0`. It
contains a contiguous range of carrier inputs, an ordinary ownership/pointer
output, and exactly one SEQUIN manifest in an OP_RETURN output.

For version-1 transactions, BIP68 does not assign relative-locktime semantics to
`nSequence`. With zero absolute locktime, the transaction is immediately final
regardless of those values. The encoder therefore maps every four consecutive
content bytes to one unsigned little-endian `nSequence`. The final group is
zero-padded to four bytes.

Signatures commit to the sequences and input order. Individual values can
incidentally signal or disable BIP125 replacement, so replaceability must never
be used as framing.

## Version 1 manifest

All integers are unsigned little-endian.

| Offset | Bytes | Field |
|---:|---:|---|
| 0 | 4 | magic `SEQN` |
| 4 | 1 | version (`1`) |
| 5 | 1 | flags (`0`, raw content) |
| 6 | 2 | first carrier input index |
| 8 | 2 | carrier input count |
| 10 | 2 | ownership/pointer vout |
| 12 | 4 | exact content byte length |
| 16 | 32 | SHA-256 of decoded content |
| 48 | 1 | MIME byte length |
| 49 | 1..31 | ASCII MIME type |

The manifest is at most 80 bytes. Its minimal script is at most 83 bytes:
`OP_RETURN OP_PUSHDATA1 0x50 <80 bytes>`.

## Canonical decoding

A v1 decoder must:

1. reject unknown magic, version, flags, or non-ASCII/empty MIME values;
2. require `input_count == ceil(content_length / 4)`;
3. reject an input range that exceeds the reveal's input vector;
4. serialize each selected uint32 sequence little-endian in transaction order;
5. truncate to `content_length` and reject non-zero trailing padding; and
6. require the decoded SHA-256 to match the manifest.

The included `sequin.py` implements these rules.

## Ownership and identity

The manifest names one output as its pointer. The proof creates that output as a
wallet-controlled P2TR output and demonstrates a later spend. A production
indexer still needs explicit transfer, burn, duplicate-manifest, reorg, and
conflict rules. Until those exist, the confirmed reveal txid is the stable
artifact identifier and the pointer is only a demonstrated ownership primitive.

## Limitations

- Capacity is four bytes per input and is not witness-discounted.
- Fanout construction and reveal signing are costly for even small media.
- The fanout is not a content commitment; the issuer chooses content at reveal.
- The confirmed reveal, not an unconfirmed txid, is authoritative because some
  sequence patterns opt into replacement.
- The design depends on current transaction semantics and local relay policy.
- RDTS deployment state and expiry must be checked for the target chain height.

SEQUIN's virtue is not efficiency. It is that its data path uses ordinary
transaction fields and leaves no persistent carrier UTXO set behind.
