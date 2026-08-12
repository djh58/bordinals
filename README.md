# Knotscribe

**Knotscribe** is a research repository for inscription-like data transports on
Bitcoin Knots with BIP-110/RDTS active. It aims to tie data into transactions
without tying up permanent junk UTXOs.

> [!WARNING]
> This is experimental research, not a production NFT protocol. Relay policy is
> version- and operator-dependent. Validate every construction against the exact
> Knots revision and configuration you intend to use.

The repository contains two related designs:

| Design | Status | Capacity | Current-policy posture |
|---|---|---:|---|
| **SEQUIN** — **SEQU**ence **IN**scription | Implemented and regtest-verified | 4 bytes/input | Uses ordinary input metadata and one standard OP_RETURN manifest |
| **DROPSTITCH** | Implemented and regtest-verified | 1,500 bytes/input | Relies on a narrow `OP_2DROP` scanner gap; deliberately brittle |

SEQUIN is the conservative design. DROPSTITCH is 375 times denser and has a
working authenticated P2WSH implementation, but it is intentionally not
presented as stable or future-proof.

## How SEQUIN works

1. A fanout transaction creates `ceil(payload_bytes / 4)` ordinary,
   wallet-controlled outputs.
2. A version-1 reveal transaction with `nLockTime=0` spends them in a defined
   order. Each input's full 32-bit `nSequence` carries four bytes in transaction
   wire order.
3. Output 0 is an ordinary spendable P2TR ownership pointer. A second output is
   an at-most-80-byte OP_RETURN manifest containing framing, MIME type, exact
   length, and SHA-256.
4. A decoder reads the confirmed transaction, reconstructs the selected input
   sequences, removes canonical zero padding, and verifies the hash.

No fake keys, witness envelopes, burned outputs, or permanent carrier UTXOs are
required. The tradeoff is poor density: every four payload bytes require one
funded and signed input.

Both transports accept arbitrary bytes, so SVG, PNG, JPEG, GIF, and WebP are no
different from text to the codec. SEQUIN's low capacity favors tiny SVGs, pixel
art, or hashes. DROPSTITCH can fit roughly 330 KB in a conservative
near-standard-weight reveal, subject to fees and policy remaining unchanged.
That 330 KB transaction is relay-standard and consensus-valid, but larger than
Knots' separate default 300 kB block-template byte target.

See [the SEQUIN protocol note](docs/SEQUIN.md) and
[the DROPSTITCH protocol note](docs/DROPSTITCH.md) for details.

## Quick start

The codec uses only Python's standard library:

```sh
python3 -m unittest -v test_sequin.py test_dropstitch.py
python3 sequin.py encode ./art.svg --mime image/svg+xml
python3 dropstitch.py encode ./art.svg \
  --mime image/svg+xml \
  --pubkey "$COMPRESSED_PUBKEY_HEX"
```

Each `encode` command prints a manifest, standard OP_RETURN script, and carrier
values as JSON. DROPSTITCH requires that exact manifest OP_RETURN in both the
common funding transaction and reveal transaction. The supplied compressed
secp256k1 key must be a key you control; the codec builds committed scripts but
deliberately does not manage private keys or broadcast transactions.

Decode a SEQUIN artifact back to a file with:

```sh
python3 sequin.py decode \
  --manifest MANIFEST_HEX \
  --output recovered.svg \
  0x01234567 0x89abcdef
```

Or decode DROPSTITCH witness scripts with:

```sh
python3 dropstitch.py decode \
  --funding-manifest MANIFEST_HEX \
  --reveal-manifest MANIFEST_HEX \
  --pubkey "$COMPRESSED_PUBKEY_HEX" \
  --output recovered.svg \
  SIGNATURE_HEX:WITNESS_SCRIPT_HEX [...]
```

The two manifest arguments must be extracted independently from the common
funding transaction and the reveal. Supply witness stacks only from a reveal
that a full node has consensus-validated: the standalone codec checks canonical
DER/low-S/`SIGHASH_ALL` framing and the content hash, but intentionally does not
implement Bitcoin transaction parsing, prevout ancestry, or ECDSA evaluation.

## Run the two-node Knots proof

Build a checkout of the Knots `29.x-knots` line with RDTS consent:

```sh
cd /path/to/bitcoin-knots
cmake -S . -B build-knotscribe -GNinja \
  -D RDTS_CONSENT=IMPLICIT \
  -D BUILD_GUI=OFF \
  -D BUILD_TESTS=OFF \
  -D BUILD_BENCH=OFF \
  -D BUILD_UTIL=OFF \
  -D BUILD_TX=OFF \
  -D BUILD_WALLET_TOOL=OFF
cmake --build build-knotscribe -j 8 --target bitcoind bitcoin-cli
```

Then, from this repository:

```sh
BITCOIN_KNOTS_REPO=/path/to/bitcoin-knots \
python3 sequin_regtest.py \
  --configfile=/path/to/bitcoin-knots/build-knotscribe/test/config.ini \
  --loglevel=INFO

BITCOIN_KNOTS_REPO=/path/to/bitcoin-knots \
python3 dropstitch_regtest.py \
  --configfile=/path/to/bitcoin-knots/build-knotscribe/test/config.ini \
  --loglevel=INFO
```

The tests start two connected nodes, activate RDTS on regtest, and explicitly
restore Knots policy with `-corepolicy=0` because the upstream functional-test
harness otherwise injects Core policy. It proves:

- fanout and reveal relay to a second default-policy node;
- byte-identical DROPSTITCH manifests in funding and reveal;
- reveal acceptance by `testmempoolaccept`;
- byte-exact reconstruction and SHA-256 verification from signed wire data;
- consumption of every fanout output into one ordinary P2TR pointer; and
- a standard subsequent spend of that pointer.

Each also proves the policy/consensus boundary with a literal `OP_DROP` P2WSH
negative control. It is rejected from the mempool as
`txn-datacarrier-nonstandard`, yet accepted when directly included in an
RDTS-active block; DROPSTITCH's control additionally requires a valid signature.

For capacity exercises, SEQUIN accepts `--stress-inputs=1650` (6,600 bytes).
DROPSTITCH accepts `--stress-inputs=177` for a conservatively default-template-
mineable 265,500-byte reveal, or `--stress-inputs=220` for a 330,000-byte reveal
that is relay-standard and consensus-valid but exceeds the compiled 300 kB
block-template byte target. Confirming the fanout before a large reveal is
important because an unconfirmed pair can exceed default ancestor-size policy.

## Verified scope

The included proofs were run on 2026-08-12 against Bitcoin Knots commit
`2d531eaf4b0801278b3e928cf9df3b3852001d0a` from `origin/29.x-knots` and its
compiled policy defaults.

- SEQUIN's 524-byte SVG used 131 inputs.
- DROPSTITCH's 5,025-byte SVG used four authenticated P2WSH inputs whose complete
  signed witnesses were at most 1,638 bytes under the 1,650-byte default ceiling.
- A 177-input/265,500-byte DROPSTITCH reveal was selected by the default block
  template. A 220-input/330,000-byte reveal was accepted and relayed at about
  396.9 kWU, then explicitly included to prove consensus after the default
  300 kB template target left its roughly 369.4 kB serialization in the mempool.

Both relayed between two nodes, reconstructed exactly, consumed every temporary
carrier, left one spendable P2TR output, and successfully swept that output.

That demonstrates behavior for the tested revision. It does not promise that a
future release, a differently configured peer, or a miner will retain the same
policy.

## License

MIT. See [LICENSE](LICENSE).
