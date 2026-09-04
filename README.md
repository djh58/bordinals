# BORDINALS

**BORDINALS** is a proof-of-concept inscription/NFT data transport for Bitcoin
Knots with BIP-110/RDTS active. The name combines **BLAKE2b** with **ordinals**.
It carries arbitrary bytes—including SVG, PNG, JPEG, GIF, and WebP—without
leaving permanent carrier UTXOs.

> [!WARNING]
> This is experimental research, not a production NFT protocol. Relay policy is
> version- and operator-dependent. Validate every construction against the exact
> Knots revision and configuration you intend to use.

The repository contains two designs:

| Design | Capacity | Tradeoff |
|---|---:|---|
| **BORDINALS** | 1,500 bytes/input | Dense authenticated P2WSH carriers; relies on a narrow `OP_2DROP` policy-scanner gap |
| **SEQUIN** — **SEQU**ence **IN**scription | 4 bytes/input | Conservative ordinary-input metadata; expensive and low-density |

BORDINALS is 375 times denser and is the main implementation. SEQUIN remains as
a conservative comparison. BORDINALS v1 supersedes the earlier experimental
DROPSTITCH namespace and intentionally does not decode old `DSTC`/`DST1` data.

## How BORDINALS works

1. Split the file into 1,500-byte carriers made from six 250-byte pushes.
2. Pair each two pushes with `OP_2DROP`, then require a compressed-key
   `OP_CHECKSIG`. Each P2WSH carrier is committed and authenticated.
3. Anchor one `BORD` manifest in both the funding and reveal transactions. It
   records framing, MIME type, exact length, and BLAKE2b-256 content digest.
4. Spend every carrier with Knots' unified SIGHASH_ALL (`0x21`) into an ordinary
   P2TR ownership pointer plus the repeated manifest.
5. Reconstruct the bytes from the consensus-validated reveal and verify the
   manifest digest.

The P2WSH output still uses `SHA256(witnessScript)`. That is a SegWit-v0
consensus rule and was not changed by Knots' BLAKE2b proof-of-work fork.

## How SEQUIN differs

SEQUIN stores four bytes in each input's `nSequence`, then uses a standard
OP_RETURN manifest and ordinary P2TR ownership output. It does not depend on the
`OP_2DROP` scanner seam, but a 524-byte SVG needs 131 funded and signed inputs.
Its independent v1 namespace continues using SHA-256.

Both codecs treat images as opaque bytes. BORDINALS is practical for larger
images: this transaction shape guarantees that 221 inputs carrying 331,500
bytes remain under the current 400 kWU standard-transaction ceiling. SEQUIN is
better suited to tiny SVGs, pixel
art, thumbnails, or content hashes.

See [the BORDINALS protocol note](docs/BORDINALS.md) and
[the SEQUIN protocol note](docs/SEQUIN.md) for the exact wire rules. The guarded
transaction workflow is documented in [Mainnet workflow](docs/MAINNET.md).

## Quick start

The codecs use only Python's standard library:

```sh
python3 -m unittest -v test_sequin.py test_bordinals.py

python3 bordinals.py encode ./art.svg \
  --mime image/svg+xml \
  --pubkey "$COMPRESSED_PUBKEY_HEX"
```

The low-level encoder prints the binary manifest, standard OP_RETURN script,
carrier witnessScripts, and P2WSH scriptPubKeys as JSON. It never touches a
wallet or broadcasts.

`bordinals_mint.py` is a separate, experimental transaction tool. It funds each
opt-in recipient as an independent job, signs both a reveal and emergency
refund before any broadcast is possible, and writes an integrity-checked
mode-0600 schema-v2 plan. Every plan requires a sibling append-only execution
journal named `PLAN.state.jsonl`; for example, `bordinals-plan.json` is paired
with `bordinals-plan.json.state.jsonl`. The journal is also mode 0600. It
durably records selected inputs before they are persistently locked, the
committed plan binding, funding-attempt state before the submission RPC, and
the irreversible reveal-or-refund choice. Missing, corrupt, truncated, or
mismatched journal state causes broadcast and unlock to fail closed; read-only
status can still inspect the immutable plan and chain without it.

Commands are read-only unless `--execute` is supplied; preparation itself
never broadcasts, and funding, reveal, and refund are separate steps with
fresh policy checks. Minting is pinned to the exact latest audited mainnet
build, `v29.4.1.knots20260508`. Status and emergency refund use a
wallet-independent chain-identity gate, so the tool does not reject recovery
solely because consent expired, the wallet is unloaded, RDTS expired, or the
node was upgraded. The exact refund must still pass the connected node's
current relay policy.
Move and back up a plan and its journal together. The journal is an
owner-controlled crash-recovery and audit record, not a global anti-rollback
mechanism: an operator who can restore files can restore old local state.
Keep one canonical plan/journal directory and never execute copied pairs on
multiple hosts.

The recipient file is intentionally strict. External records must bind the
fresh P2TR address, gift amount, artifact BLAKE2b-256, chain, consent reference,
and expiration. A reference records the operator's workflow; it is not
cryptographic proof of consent. The tool does not discover or attribute
people's financial addresses.

Decode consensus-validated BORDINALS witness stacks with:

```sh
python3 bordinals.py decode \
  --funding-manifest MANIFEST_HEX \
  --reveal-manifest MANIFEST_HEX \
  --pubkey "$COMPRESSED_PUBKEY_HEX" \
  --output recovered.svg \
  SIGNATURE_HEX:WITNESS_SCRIPT_HEX [...]
```

The manifests must be independently extracted from the common funding
transaction and reveal. The standalone decoder checks their byte identity,
strict DER/low-S/`0x21` framing, carrier shape, and BLAKE2b-256. It intentionally
does not implement transaction parsing, prevout ancestry, or ECDSA evaluation;
feed it only witnesses already validated by a full node.

SEQUIN's CLI remains available:

```sh
python3 sequin.py encode ./tiny.svg --mime image/svg+xml
python3 sequin.py decode \
  --manifest MANIFEST_HEX \
  --output recovered.svg \
  0x01234567 0x89abcdef
```

## Run the latest-Knots proof

The current verification target is Bitcoin Knots
`v29.4.1.knots20260508` (`8c85b1585dac23f964e2dd32045624de7f02aa58`).

```sh
git clone https://github.com/bitcoinknots/bitcoin.git bitcoin-knots
cd bitcoin-knots
git checkout v29.4.1.knots20260508

cmake -S . -B build-bordinals -GNinja \
  -D BUILD_GUI=OFF \
  -D BUILD_TESTS=OFF \
  -D BUILD_BENCH=OFF \
  -D BUILD_UTIL=OFF \
  -D BUILD_TX=OFF \
  -D BUILD_WALLET_TOOL=OFF
cmake --build build-bordinals -j 8 --target bitcoind bitcoin-cli
```

Then, from this repository:

```sh
BITCOIN_KNOTS_REPO=/path/to/bitcoin-knots \
python3 bordinals_regtest.py \
  --configfile=/path/to/bitcoin-knots/build-bordinals/test/config.ini \
  --loglevel=INFO

BITCOIN_KNOTS_REPO=/path/to/bitcoin-knots \
python3 sequin_regtest.py \
  --configfile=/path/to/bitcoin-knots/build-bordinals/test/config.ini \
  --loglevel=INFO

BITCOIN_KNOTS_REPO=/path/to/bitcoin-knots \
python3 bordinals_mint_regtest.py \
  --configfile=/path/to/bitcoin-knots/build-bordinals/test/config.ini \
  --loglevel=INFO
```

The tests start two connected nodes with BLAKE2b/RDTS active and compiled Knots
relay defaults. They set `-corepolicy=0` only because Knots' functional harness
otherwise injects Core policy. They prove:

- default-policy funding and reveal relay to a second peer;
- the funding and reveal carry byte-identical BORDINALS manifests;
- the reveal uses unified `0x21` signatures and passes `testmempoolaccept`;
- the image reconstructs byte-for-byte and passes BLAKE2b-256 verification;
- all temporary carriers are consumed into one spendable P2TR pointer; and
- the pointer can be relayed, mined, and swept normally.

The guarded-minter proof additionally uses the same Knots wallet/RPC boundary
as the CLI. It proves that the default preview is inert, executed preparation
creates the bound plan/journal pair, persistent input locks survive a node
restart, a P2TR wallet coin receives the unified funding signature, a
multi-carrier funding/reveal pair relays after a confirmation boundary, and a
second CLI plan's independently pre-signed refund recovers every carrier into
a wallet-owned P2TR output even after consent expires and the wallet is
unloaded.

Each proof also constructs a literal `<data> OP_DROP` P2WSH control. Knots
rejects it from the mempool as `txn-datacarrier-nonstandard`, then accepts the
same transaction when explicitly included in an RDTS-valid block. This brackets
the policy/consensus distinction that BORDINALS relies on.

Capacity exercises:

```sh
# Reliably selected by the default 300 kB template target:
python3 bordinals_regtest.py ... --stress-inputs=177

# Largest conservatively guaranteed-standard case; explicitly mined after relay:
python3 bordinals_regtest.py ... --stress-inputs=221
```

Confirming the carrier funding transaction before a large reveal is important:
an unconfirmed pair can exceed default ancestor-package policy.

## Verified scope

On 2026-09-03 the included proofs passed against the latest official Knots
release, `v29.4.1.knots20260508`, at commit
`8c85b1585dac23f964e2dd32045624de7f02aa58`:

- The 5,024-byte SVG used four carriers, relayed across two default-policy
  nodes, reconstructed exactly, confirmed, and left a spendable P2TR pointer.
- The 177-input/265,500-byte reveal relayed and was selected by the default
  template at about 297.2 kB and below 319.6 kWU.
- The 221-input/331,500-byte reveal relayed at about 371.1 kB and below
  398.8 kWU. The 300 kB template target left it in the mempool, after which
  explicit block inclusion proved consensus acceptance under RDTS' 800 kWU cap.
- SEQUIN's 524-byte/131-input image proof still relayed, reconstructed, and
  swept successfully on the same release.
- The guarded minter created wallet-funded transactions, matched Knots'
  `UnifiedSighash` on an independent test vector, signed a P2TR funding coin,
  relayed a multi-input recipient reveal, and exercised its confirmed-funding
  emergency refund on two default-policy nodes.

This demonstrates the tested revision and defaults; it does not promise a
future release, differently configured peer, or miner will preserve the policy
seam. The minter statically checks Knots' Counterparty predicate and requires
the exact funding/reveal and funding/refund packages to pass
`testmempoolaccept` before it will save a broadcastable plan. Knots' token
filter still has an approximately 2^-64 accidental-match edge case for any
single-push OP_RETURN; a detected collision fails closed.

## License

MIT. See [LICENSE](LICENSE).
