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
| **DROPSTITCH** | Design note only | roughly 1.5 KB/input | Relies on a narrow `OP_2DROP` scanner gap; likely brittle |

SEQUIN is the conservative proof of concept. DROPSTITCH is documented because
it is substantially denser, but it is intentionally not presented as stable or
future-proof.

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

See [the SEQUIN protocol note](docs/SEQUIN.md) and
[the DROPSTITCH design note](docs/DROPSTITCH.md) for details.

## Quick start

The codec uses only Python's standard library:

```sh
python3 test_sequin.py
python3 sequin.py encode ./art.svg --mime image/svg+xml
```

`encode` prints the manifest, standard OP_RETURN script, and exact unsigned
`nSequence` integers as JSON. Decode them back to a file with:

```sh
python3 sequin.py decode \
  --manifest MANIFEST_HEX \
  --output recovered.svg \
  0x01234567 0x89abcdef
```

## Run the two-node Knots proof

Build a checkout of the Knots `29.x-knots` line with RDTS consent:

```sh
cd /path/to/bitcoin-knots
cmake -S . -B build-sequin -GNinja \
  -D RDTS_CONSENT=IMPLICIT \
  -D BUILD_GUI=OFF \
  -D BUILD_TESTS=OFF \
  -D BUILD_BENCH=OFF \
  -D BUILD_UTIL=OFF \
  -D BUILD_TX=OFF \
  -D BUILD_WALLET_TOOL=OFF
cmake --build build-sequin -j 8 --target bitcoind bitcoin-cli
```

Then, from this repository:

```sh
BITCOIN_KNOTS_REPO=/path/to/bitcoin-knots \
python3 sequin_regtest.py \
  --configfile=/path/to/bitcoin-knots/build-sequin/test/config.ini \
  --loglevel=INFO
```

The test starts two connected nodes, activates RDTS on regtest, and explicitly
restores Knots policy with `-corepolicy=0` because the upstream functional-test
harness otherwise injects Core policy. It proves:

- fanout and reveal relay to a second default-policy node;
- reveal acceptance by `testmempoolaccept`;
- byte-exact reconstruction and SHA-256 verification from signed wire data;
- consumption of every fanout output into one ordinary P2TR pointer; and
- a standard subsequent spend of that pointer.

It also proves the policy/consensus boundary with a negative control: a P2WSH
`<data> OP_DROP OP_TRUE` spend is rejected from the mempool as
`txn-datacarrier-nonstandard`, yet accepted when directly included in an
RDTS-active block.

Add `--stress-inputs=1650` for a 6,600-byte, near-standard-weight exercise.

## Verified scope

The included proof was run on 2026-08-12 against the workspace's
`origin/29.x-knots` code and compiled defaults. The 524-byte SVG case used 131
carrier inputs, relayed between two nodes, reconstructed exactly, left one
spendable P2TR output, and successfully swept that output.

That demonstrates behavior for the tested revision. It does not promise that a
future release, a differently configured peer, or a miner will retain the same
policy.

## License

MIT. See [LICENSE](LICENSE).
