# Guarded mainnet workflow

`bordinals_mint.py` can prepare and broadcast BORDINALS transactions through a
locally authenticated Bitcoin Knots wallet. It is experimental software, not a
production wallet, marketplace, or complete NFT protocol.

The mainnet profile is deliberately pinned to Bitcoin Knots
`v29.4.1.knots20260508` (`8c85b1585dac23f964e2dd32045624de7f02aa58`).
Preparation and delivery broadcasts check the node identity, mainnet genesis,
height-961640 activation checkpoint, v2 tip header, active BLAKE2b and RDTS
deployments, RDTS expiry, and sync state. Preparation also checks wallet
capabilities. A later Knots version needs a new audited minting profile even if
its version number is higher. Status and emergency refund intentionally use a
narrower chain-identity check so an already-signed recovery is not disabled by
an unloaded wallet, expired consent record, RDTS expiry, or node upgrade.
Read-only status needs only the immutable plan and chain; executing the refund
still requires its exact bound journal.

> [!CAUTION]
> Preparing a plan reserves confirmed wallet UTXOs and derives refund
> addresses, but does not broadcast. Broadcasting spends real coins. Use a
> dedicated, backed-up Knots wallet with only the amount you intend to spend;
> never import a live Bitcoin seed into experimental software.

Each schema-v2 plan has a required sibling append-only execution journal. If
the plan is `bordinals-plan.json`, its journal is
`bordinals-plan.json.state.jsonl`. Treat the two files as one recovery unit:
both are mode 0600, and you must move, copy, and back them up together. Any
broadcast or unlock command fails closed if the journal is missing, corrupt,
truncated, or bound to a different plan. Keep one canonical plan/journal
directory as the sole operational authority; do not run copied pairs
concurrently or independently on another host. An incomplete pre-commit
journal remains readable for exact manual recovery, but it cannot authorize
execution as a committed plan pair. The `status` command is the deliberate
exception: it is read-only and can inspect the immutable plan and chain without
the journal.

## Recipient consent file

Compute the artifact digest:

```sh
python3 -c 'import hashlib,sys; print(hashlib.blake2b(open(sys.argv[1],"rb").read(),digest_size=32).hexdigest())' art.svg
```

Create `recipients.json`. Each external recipient should supply a fresh
Knots-side P2TR address after seeing the exact artifact digest and gift amount:

```json
{
  "schema": "bordinals-consent/1",
  "chain": "main",
  "artifact_blake2b256": "REPLACE_WITH_64_HEX_CHARACTERS",
  "entries": [
    {
      "address": "REPLACE_WITH_A_FRESH_BC1P_ADDRESS",
      "gift_sats": 2000,
      "label": "optional private label",
      "consent": {
        "mode": "reference",
        "reference": "ticket-or-message-record-id",
        "obtained_at": "2026-09-03T20:00:00Z",
        "expires_at": "2026-10-03T20:00:00Z"
      }
    }
  ]
}
```

For an address controlled by the funding wallet, use only
`{"mode":"self"}`. The tool asks the wallet to prove `ismine`; external
records require a unique, unexpired reference. A reference is an operator
attestation, not a BIP322 signature and not cryptographic proof of consent.

The tool will not discover wallet addresses, connect identities to financial
addresses, or infer consent from an address published for some other purpose.

## Preview, then prepare without broadcasting

An external-reference-only preview does not need a loaded funding wallet or
`--wallet`. A `self` recipient does require the wallet-scoped RPC so the preview
can prove that the address is wallet-owned. Executed preparation always
requires `--wallet`; that wallet must be loaded, unlocked if encrypted, and
have confirmed native-SegWit UTXOs. Wrapped P2SH-SegWit inputs are refused so
the PSBT's pre-signing txid cannot change when scriptSig is finalized. Do not
start Knots with `-walletoldsigs`; funding is explicitly signed with
`ALL|UNIFIED`.

```sh
python3 bordinals_mint.py prepare art.svg \
  --mime image/svg+xml \
  --recipients recipients.json \
  --plan-out bordinals-plan.json \
  --wallet bordinals \
  --bitcoin-cli /path/to/bitcoin-cli \
  --fee-rate-sat-vb 2 \
  --max-fee-rate-sat-vb 10 \
  --max-total-fee-sats 5000000 \
  --max-total-spend-sats 5000000 \
  --acknowledge-recipient-consent 'I CONFIRM EVERY RECIPIENT OPTED IN' \
  --acknowledge-mainnet 'I UNDERSTAND THIS LOCKS REAL MAINNET COINS'
```

That command is a read-only preview. It validates the chain profile, consent
records, addresses, dust, carrier count, and conservative reveal/refund costs;
it checks wallet ownership only for `self` entries. It does not derive an
address, select or lock a coin, sign, write the requested plan or journal, or
call `testmempoolaccept`; the exact funding fee is necessarily unknown before
coin selection. `--acknowledge-mainnet` is enforced only by `prepare --execute`
and is not required for this preview.

After reviewing the preview, repeat the same command with `--execute`. Only
this second invocation creates the bound plan/journal pair and persistently
reserves wallet UTXOs:

```sh
python3 bordinals_mint.py prepare art.svg ... \
  --plan-out bordinals-plan.json \
  --execute
```

Preparation performs the following for each recipient independently:

1. Generates one ephemeral carrier key with the operating system CSPRNG.
2. Builds the canonical carrier scripts and wallet-funded transaction.
3. Requires every wallet funding signature to opt into `0x21` unified sighash.
4. Signs the exact two-output recipient reveal locally.
5. Signs a conflicting emergency refund to a new wallet-owned P2TR address.
6. Locally verifies every reveal/refund signature and all prevouts, scripts,
   outputs, fees, digests, and weights; checks the funding txid, witness framing,
   and explicit `0x21` suffix; and leaves funding consensus-signature validation
   to Knots' exact package preflight.
7. Checks both OP_RETURNs against Knots' Counterparty RC4 predicate.
8. Requires the exact funding/reveal and funding/refund packages to pass
   `testmempoolaccept` with no ignored rejection reasons.
9. Appends and syncs the exact selected inputs to the journal before promoting
   their locks into the wallet database, so those locks survive a node restart.
10. Discards the carrier private key, writes signed transactions and metadata
    (never the ephemeral key) to a new mode-0600 schema-v2 plan, and appends a
    journal record binding that exact plan checksum.

The stock Knots wallet, `signrawtransactionwithkey`, PSBT signer, and
`bitcoin-tx` cannot solve the deliberately nonstandard inner witnessScript.
The minter therefore contains a narrow pure-Python RFC6979 secp256k1 signer and
the exact Knots v29.4.1 unified SegWit-v0 preimage. The unit suite checks that
digest against an independently generated Knots v29.4.1
`UnifiedSignatureHash` vector. The functional test then makes Knots validate,
relay, and mine transactions carrying signatures produced by that
implementation. Python big-integer arithmetic is not constant-time, which is
one reason this remains an experimental tool. The key is one-use, never
persisted, and both spend alternatives are signed before it is discarded.

Review `totals`, each recipient, all fee caps, and the displayed
`checksum_blake2b256` in the resulting plan. `plan_id` is only a convenient
label; mainnet approval and the journal binding use the full checksum. The
unkeyed checksum and hash-chained journal detect accidental or partial changes,
but neither is an authentication signature. Both files are controlled by their
owner, who can replace them together with an older backup; this is not a global
anti-rollback system. The plan contains signed transactions and private
campaign metadata, though no private key or RPC credential; protect and back
up both files together.

If you decide not to proceed, release one untouched entry's reserved wallet
inputs. Unlock requires the exact bound journal, an explicit entry, and the
acknowledgement that no funding attempt was made:

```sh
python3 bordinals_mint.py unlock bordinals-plan.json \
  --entry 0 \
  --wallet bordinals \
  --bitcoin-cli /path/to/bitcoin-cli \
  --acknowledge 'I CONFIRM THIS EXACT FUNDING TRANSACTION WAS NEVER SUBMITTED BY ANY MEANS'
```

That reports the exact locks that would be released. Add `--execute` to unlock
only those outpoints; the acknowledgement is enforced for that executed
mutation and may be omitted from a dry-run inspection. The command refuses an
unrelated same-named wallet by proving ownership of the plan's exact saved
refund key before it changes journal or lock state. It also refuses an
entry if its journal records a funding attempt, even if the transaction is not
currently visible to the node; an RPC timeout may have followed a successful
submission. Entries are selected and acknowledged independently, and journal
state for other entries is not treated as permission to unlock this one. The
intact journal proves only the narrower fact that this tool recorded no funding
attempt. The acknowledgement additionally asserts that nobody submitted the
exact raw transaction manually, from a copied pair, through another node, or
from another host. The software cannot prove that broader fact; establishing
it is the operator's responsibility.

## Broadcast funding

Mainnet execution only accepts one numeric entry per invocation. Replace
`PLAN_CHECKSUM` with the exact full checksum printed by preparation:

```sh
python3 bordinals_mint.py broadcast bordinals-plan.json \
  --stage funding \
  --entry 0 \
  --bitcoin-cli /path/to/bitcoin-cli \
  --approve-plan-checksum PLAN_CHECKSUM \
  --acknowledge 'I UNDERSTAND THIS BROADCASTS REAL MAINNET COINS' \
  --execute
```

Without `--execute`, `broadcast` runs the same exact checks and preflights but
does not submit anything. Immediately before an executed send, the tool reruns
the chain/profile checks and both package preflights. `sendrawtransaction` is
called with the plan's nonzero fee ceiling, zero burn allowance, and an empty
ignore list. Before calling that RPC, the CLI appends and syncs a funding-attempt
record to the journal. Repeating the command reconciles mempool and confirmed
state by the precomputed txid and exact outputs, but a recorded attempt can
never be treated as safe evidence for unlocking the original wallet inputs.

Wait for at least one confirmation. Large fanouts must not reveal against an
unconfirmed funding transaction because ancestor-package limits are separate
from each transaction's standardness.

## Broadcast the reveal

```sh
python3 bordinals_mint.py status bordinals-plan.json \
  --bitcoin-cli /path/to/bitcoin-cli

python3 bordinals_mint.py broadcast bordinals-plan.json \
  --stage reveal \
  --entry 0 \
  --min-confirmations 1 \
  --bitcoin-cli /path/to/bitcoin-cli \
  --approve-plan-checksum PLAN_CHECKSUM \
  --acknowledge 'I UNDERSTAND THIS BROADCASTS REAL MAINNET COINS' \
  --execute
```

The tool rechecks that every exact carrier UTXO remains unspent and reruns
single-transaction `testmempoolaccept` before broadcasting. The recipient gets
the exact `gift_sats` P2TR output at vout 0. They can spend that output normally;
BORDINALS v1 does not impose an on-chain transfer or burn rule. Before the
submission RPC, the journal durably chooses `reveal` for this entry. A later
refund request fails closed even if the reveal RPC times out or the local node
does not yet report the transaction.

After a successful reveal, do not broadcast its refund: the two transactions
spend the same carriers and intentionally conflict.

## Emergency refund instead of delivery

If funding confirmed but you decide not to deliver, inspect the saved refund
and explicitly select it instead:

```sh
python3 bordinals_mint.py broadcast bordinals-plan.json \
  --stage refund \
  --entry 0 \
  --min-confirmations 1 \
  --bitcoin-cli /path/to/bitcoin-cli \
  --approve-plan-checksum PLAN_CHECKSUM \
  --acknowledge 'I UNDERSTAND THIS BROADCASTS REAL MAINNET COINS' \
  --acknowledge-refund 'I CHOOSE REFUND INSTEAD OF THE RECIPIENT DELIVERY' \
  --execute
```

The refund still reveals the carrier witnessScripts on chain, but it has no
BORD manifest and returns the carrier value minus its fee to the recorded
wallet-owned P2TR address. It is a financial recovery path, not content
secrecy. A future policy change that rejects the carrier script itself can also
stop refund relay, even though the spend may remain consensus-valid. The
journal durably chooses `refund` before submission, making reveal and refund
locally mutually exclusive even across an ambiguous RPC failure.

## Limits and failure behavior

- Default preparation accepts at most 177 carriers (265,500 artifact bytes).
- The hard audited ceiling is 221 carriers (331,500 bytes) and requires
  `--max-carriers 221 --acknowledge-large-transaction 'I ACCEPT A 178-221 CARRIER EXPERIMENT'`.
- Preparation also requires the two-transaction packages to pass current
  package policy. A near-maximum reveal plus funding may exceed the package
  size limit and fail safely even though the reveal alone is standard after
  funding confirms.
- Every carrier output and P2TR pointer must meet the connected node's current
  dynamic dust threshold.
- The default fee-rate ceiling is 10 sat/vB; funding, reveal, aggregate-fee,
  and aggregate-spend caps are enforced independently.
- There is no fee bump after preparation because the ephemeral key is gone.
  Choose a realistic rate, reveal promptly after confirmation, and use only
  money you can afford to have temporarily stranded.
- RDTS is temporary. Funding preparation and broadcast require seven days of
  median-time headroom, and reveal checks activation again. Refund and status
  keep working through the narrower chain-identity path after RDTS expiry.
- On a detected preparation failure, the tool attempts to release and then
  reconcile only the exact newly selected wallet inputs. If cleanup cannot be
  confirmed, it exits with a safety error listing the exact remaining or
  possibly locked outpoints. It never performs a broad wallet unlock.
- `SIGKILL`, power loss, or storage failure can interrupt the interval between
  the journaled selection, persistent wallet lock, plan commit, and cleanup. If
  preparation does not return a complete bound plan/journal pair, inspect the
  affected wallet with `listlockunspent`, compare only the exact outpoints in
  the surviving journal, and verify transaction history before manually
  unlocking anything. Never use an unlock-all recovery command.
- The journal is local, append-only state for crash safety and operator review.
  It is not a network consensus record, a third-party timestamp, or protection
  against an owner deliberately rolling back both files.

## Verification

Run the standard-library tests:

```sh
python3 -B -m unittest -v \
  test_sequin.py test_bordinals.py test_bordinals_mint.py
```

Run the exact RPC/wallet/relay proof against a built Knots v29.4.1 tree:

```sh
BITCOIN_KNOTS_REPO=/path/to/bitcoin-knots \
python3 bordinals_mint_regtest.py \
  --configfile=/path/to/bitcoin-knots/build-bordinals/test/config.ini \
  --loglevel=INFO
```

The proof starts two RDTS-active nodes with compiled Knots policy defaults,
checks that the default preview writes neither plan nor journal, executes
preparation and validates the bound schema-v2 plan/journal pair, verifies that
persistent locks survive restart, funds from a P2TR wallet coin, relays and
confirms a multi-carrier reveal, reconstructs the neutral SVG exactly, then
runs a second complete CLI plan whose refund remains usable after its consent
expires and the funding wallet is unloaded.
