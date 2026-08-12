#!/usr/bin/env python3
"""End-to-end DROPSTITCH proof on two default-policy, RDTS-active Knots nodes.

This test intentionally uses the Bitcoin Knots functional test framework.  It
proves the current policy seam DROPSTITCH relies on; it is not a promise that a
future Knots release will continue relaying OP_2DROP carriers.
"""

from __future__ import annotations

from decimal import Decimal
import hashlib
import os
from pathlib import Path
import sys


HERE = Path(__file__).resolve().parent
candidate_repos = [
    Path(os.environ["BITCOIN_KNOTS_REPO"]).expanduser()
    if "BITCOIN_KNOTS_REPO" in os.environ
    else None,
    HERE.parent / "bitcoin",
    HERE.parent / "bitcoin-knots",
    Path.cwd(),
]
REPO = next(
    (
        candidate.resolve()
        for candidate in candidate_repos
        if candidate is not None
        and (candidate / "test" / "functional" / "test_framework").is_dir()
    ),
    None,
)
if REPO is None:
    raise RuntimeError(
        "Bitcoin Knots source tree not found; set BITCOIN_KNOTS_REPO=/path/to/bitcoin"
    )
sys.path.insert(0, str(REPO / "test" / "functional"))

from test_framework.address import (  # noqa: E402
    address_to_scriptpubkey,
    script_to_p2wsh,
)
from test_framework.key import ECKey  # noqa: E402
from test_framework.messages import (  # noqa: E402
    COIN,
    COutPoint,
    CTransaction,
    CTxIn,
    CTxInWitness,
    CTxOut,
    tx_from_hex,
)
from test_framework.script import (  # noqa: E402
    CScript,
    OP_2DROP,
    OP_CHECKSIG,
    OP_DROP,
    OP_RETURN,
    SIGHASH_ALL,
    SegwitV0SignatureHash,
)
from test_framework.test_framework import BitcoinTestFramework  # noqa: E402
from test_framework.util import assert_equal  # noqa: E402

from dropstitch import (  # noqa: E402
    MAX_PAYLOAD_BYTES,
    build_manifest,
    build_script,
    decode_committed_witnesses,
    encode_payloads,
    parse_manifest,
    parse_script,
    p2wsh_scriptpubkey,
)


VBPARAMS_RDTS_ALWAYS_ACTIVE = "-vbparams=reduced_data:-1:999999999999:0"
MAX_DEFAULT_WITNESS_BYTES = 1650
MAX_P2WSH_SCRIPT_BYTES = 3600
MAX_NON_SCRIPT_WITNESS_ITEM_BYTES = 80
MAX_STANDARD_STRESS_INPUTS = 220

CARRIER_VALUE_SATS = 250_000
CLEANUP_FEE_SATS = 10_000


def test_svg() -> bytes:
    """Return a deterministic, valid SVG large enough for multiple carriers."""
    stitches = []
    colors = ("#ff4d8d", "#ffe66d", "#52d3d8", "#8067dc")
    for index in range(48):
        x = 20 + (index % 8) * 40
        y = 38 + (index // 8) * 40
        stitches.append(
            f'<circle cx="{x}" cy="{y}" r="13" fill="{colors[index % 4]}" '
            f'stroke="#161629" stroke-width="4" data-stitch="{index}"/>'
        )
    image = (
        '<svg xmlns="http://www.w3.org/2000/svg" width="340" height="300" '
        'viewBox="0 0 340 300">'
        '<rect width="340" height="300" rx="24" fill="#161629"/>'
        + "".join(stitches)
        + '<text x="170" y="285" text-anchor="middle" font-family="monospace" '
        'font-size="18" fill="white">DROPSTITCH #1</text></svg>'
    ).encode("ascii")
    assert len(image) > MAX_PAYLOAD_BYTES
    return image


def extract_single_op_return(decoded_tx: dict) -> bytes:
    """Extract one minimally pushed OP_RETURN payload from decoded wire data."""
    null_data = [
        output
        for output in decoded_tx["vout"]
        if output["scriptPubKey"]["type"] == "nulldata"
    ]
    assert_equal(len(null_data), 1)
    script = CScript(bytes.fromhex(null_data[0]["scriptPubKey"]["hex"]))
    operations = list(script.raw_iter())
    assert_equal(len(operations), 2)
    assert_equal(operations[0][0], OP_RETURN)
    assert_equal(operations[0][1], None)
    assert operations[1][1] is not None
    return operations[1][1]


class DropstitchRegtest(BitcoinTestFramework):
    def add_options(self, parser):
        self.add_wallet_options(parser, descriptors=True, legacy=False)
        parser.add_argument(
            "--stress-inputs",
            type=int,
            default=0,
            help=(
                "replace the SVG with deterministic binary content requiring "
                "exactly N carrier inputs (maximum tested relay boundary: 220; "
                "177 conservatively fits the default block-template byte target)"
            ),
        )

    def set_test_params(self):
        self.num_nodes = 2
        self.setup_clean_chain = True
        # The harness adds -corepolicy by default.  Override only that harness
        # convenience so the nodes exercise compiled Knots policy.  No
        # datacarrier, standardness, script-size, or witness-size knobs change.
        self.extra_args = [
            [VBPARAMS_RDTS_ALWAYS_ACTIVE, "-corepolicy=0"],
            [VBPARAMS_RDTS_ALWAYS_ACTIVE, "-corepolicy=0"],
        ]

    def skip_test_if_missing_module(self):
        self.skip_if_no_wallet()

    def wait_for_mempool(self, node, txid):
        self.wait_until(lambda: txid in node.getrawmempool())

    @staticmethod
    def vout_for_address(decoded_tx, address):
        matches = [
            output["n"]
            for output in decoded_tx["vout"]
            if output["scriptPubKey"].get("address") == address
        ]
        assert_equal(len(matches), 1)
        return matches[0]

    def assert_op_drop_policy_control(self, sender, relay, key, pubkey):
        """Prove literal OP_DROP is rejected where DROPSTITCH's OP_2DROP passes."""
        control_script = CScript(
            [b"DROPSTITCH control", OP_DROP, pubkey, OP_CHECKSIG]
        )
        control_address = script_to_p2wsh(control_script)
        carrier_value = Decimal(CARRIER_VALUE_SATS) / COIN
        funding = sender.send(outputs=[{control_address: carrier_value}])
        assert_equal(funding["complete"], True)
        self.wait_for_mempool(relay, funding["txid"])
        funding_hex = sender.gettransaction(funding["txid"])["hex"]
        vout = self.vout_for_address(
            sender.decoderawtransaction(funding_hex), control_address
        )
        self.generate(sender, 1)

        destination = sender.getnewaddress(address_type="bech32m")
        spend = CTransaction()
        spend.version = 2
        spend.vin = [
            CTxIn(COutPoint(int(funding["txid"], 16), vout), nSequence=0xFFFFFFFD)
        ]
        spend.vout = [
            CTxOut(
                CARRIER_VALUE_SATS - CLEANUP_FEE_SATS,
                address_to_scriptpubkey(destination),
            )
        ]
        spend.wit.vtxinwit = [CTxInWitness()]
        sighash = SegwitV0SignatureHash(
            control_script, spend, 0, SIGHASH_ALL, CARRIER_VALUE_SATS
        )
        signature = key.sign_ecdsa(sighash, rfc6979=True) + bytes([SIGHASH_ALL])
        spend.wit.vtxinwit[0].scriptWitness.stack = [signature, control_script]
        rejection = sender.testmempoolaccept([spend.serialize().hex()])[0]
        assert_equal(rejection["allowed"], False)
        assert_equal(rejection["reject-reason"], "txn-datacarrier-nonstandard")
        self.log.info(
            "Authenticated literal OP_DROP control rejected as "
            "txn-datacarrier-nonstandard"
        )

        # Mine only to clean up and simultaneously prove RDTS consensus accepts
        # the exact policy-rejected transaction.
        self.generateblock(
            sender,
            sender.getnewaddress(address_type="bech32m"),
            [spend.serialize().hex()],
        )
        assert_equal(sender.gettxout(funding["txid"], vout), None)

    def run_test(self):
        sender, relay = self.nodes

        for node in self.nodes:
            deployment = node.getdeploymentinfo()["deployments"]["reduced_data"]
            assert_equal(deployment["bip9"]["status"], "active")
        self.log.info(
            "RDTS is active; both nodes use Knots defaults with harness "
            "-corepolicy explicitly disabled"
        )
        self.generate(sender, 101)

        if self.options.stress_inputs:
            if not 1 <= self.options.stress_inputs <= MAX_STANDARD_STRESS_INPUTS:
                raise ValueError(
                    "--stress-inputs must be between 1 and "
                    f"{MAX_STANDARD_STRESS_INPUTS}"
                )
            # Deliberately repeat one identical 1,500-byte region. The local
            # carrier index must still produce distinct scripts, addresses,
            # and outpoints for every reveal input.
            repeated_payload = hashlib.shake_256(
                b"DROPSTITCH repeated stress carrier"
            ).digest(MAX_PAYLOAD_BYTES)
            content = repeated_payload * self.options.stress_inputs
            mime = "application/octet-stream"
        else:
            content = test_svg()
            mime = "image/svg+xml"
        payloads = encode_payloads(content)
        assert len(payloads) >= 1
        assert all(len(payload) == MAX_PAYLOAD_BYTES for payload in payloads)

        key = ECKey()
        # Stable test-only secret; the functional framework key implementation
        # is explicitly not suitable for production key custody.
        key.set(
            hashlib.sha256(b"DROPSTITCH regtest signing key").digest(),
            compressed=True,
        )
        pubkey = key.get_pubkey().get_bytes()
        self.assert_op_drop_policy_control(sender, relay, key, pubkey)

        scripts = [
            build_script(payload, pubkey, carrier_index=index)
            for index, payload in enumerate(payloads)
        ]
        for index, (payload, script) in enumerate(zip(payloads, scripts)):
            assert_equal(
                parse_script(
                    script,
                    expected_pubkey=pubkey,
                    expected_index=index,
                ),
                payload,
            )
            assert len(script) <= MAX_P2WSH_SCRIPT_BYTES
            operations = list(CScript(script).raw_iter())
            assert_equal(sum(opcode == OP_2DROP for opcode, _, _ in operations), 4)
            assert_equal(sum(opcode == OP_DROP for opcode, _, _ in operations), 0)
            assert_equal(operations[-1][0], OP_CHECKSIG)

        manifest_bytes = build_manifest(
            content,
            mime,
            first_input=0,
            input_count=len(scripts),
            pointer_vout=0,
        )
        manifest = parse_manifest(manifest_bytes)
        assert_equal(manifest.input_count, len(scripts))
        assert_equal(manifest.pointer_vout, 0)
        assert_equal(manifest.content_sha256, hashlib.sha256(content).digest())
        assert len(manifest_bytes) <= 80
        self.log.info(
            f"Encoding {len(content)} bytes ({mime}) in {len(scripts)} authenticated "
            f"P2WSH carriers ({MAX_PAYLOAD_BYTES} bytes/carrier)"
        )

        # Fund temporary 34-byte P2WSH outputs.  Each commits to both its image
        # fragment and the compressed public key required by OP_CHECKSIG. The
        # same manifest is anchored here and repeated by the reveal, committing
        # exact length/hash/MIME before any carrier can be spent.
        carrier_scriptpubkeys = [p2wsh_scriptpubkey(script) for script in scripts]
        carrier_addresses = [script_to_p2wsh(script) for script in scripts]
        assert_equal(len(set(carrier_addresses)), len(carrier_addresses))
        carrier_value = Decimal(CARRIER_VALUE_SATS) / COIN
        funding = sender.send(
            outputs=[
                *({address: carrier_value} for address in carrier_addresses),
                {"data": manifest_bytes.hex()},
            ]
        )
        assert_equal(funding["complete"], True)
        funding_txid = funding["txid"]
        self.wait_for_mempool(relay, funding_txid)
        funding_hex = sender.gettransaction(funding_txid)["hex"]
        decoded_funding = sender.decoderawtransaction(funding_hex)
        manifest_from_funding = extract_single_op_return(decoded_funding)
        assert_equal(manifest_from_funding, manifest_bytes)
        self.generate(sender, 1)
        funding_manifest_vout = next(
            output["n"]
            for output in decoded_funding["vout"]
            if output["scriptPubKey"]["type"] == "nulldata"
        )
        assert_equal(sender.gettxout(funding_txid, funding_manifest_vout), None)
        self.log.info(f"Default-policy peer relayed carrier funding {funding_txid}")

        address_to_vout = {
            output["scriptPubKey"].get("address"): output["n"]
            for output in decoded_funding["vout"]
        }
        carrier_outpoints = []
        for address, scriptpubkey in zip(carrier_addresses, carrier_scriptpubkeys):
            vout = address_to_vout[address]
            carrier_outpoints.append((funding_txid, vout))
            coin = sender.gettxout(funding_txid, vout)
            assert coin is not None
            assert_equal(coin["scriptPubKey"]["type"], "witness_v0_scripthash")
            assert_equal(
                bytes.fromhex(coin["scriptPubKey"]["hex"]),
                scriptpubkey,
            )

        pointer_address = sender.getnewaddress(address_type="bech32m")
        reveal_fee_sats = max(25_000, 10_000 * len(scripts))
        pointer_value_sats = CARRIER_VALUE_SATS * len(scripts) - reveal_fee_sats
        assert pointer_value_sats > 0

        reveal = CTransaction()
        reveal.version = 2
        reveal.nLockTime = 0
        reveal.vin = [
            CTxIn(COutPoint(int(txid, 16), vout), nSequence=0xFFFFFFFD)
            for txid, vout in carrier_outpoints
        ]
        reveal.vout = [
            CTxOut(pointer_value_sats, address_to_scriptpubkey(pointer_address)),
            CTxOut(0, CScript([OP_RETURN, manifest_bytes])),
        ]
        reveal.wit.vtxinwit = [CTxInWitness() for _ in reveal.vin]
        for index, script in enumerate(scripts):
            sighash = SegwitV0SignatureHash(
                script, reveal, index, SIGHASH_ALL, CARRIER_VALUE_SATS
            )
            signature = key.sign_ecdsa(sighash, rfc6979=True) + bytes([SIGHASH_ALL])
            reveal.wit.vtxinwit[index].scriptWitness.stack = [signature, script]
        reveal_hex = reveal.serialize().hex()

        parsed_reveal = tx_from_hex(reveal_hex)
        reveal_size = len(parsed_reveal.serialize())
        reveal_weight = parsed_reveal.get_weight()
        assert reveal_weight <= 400_000
        witness_sizes = []
        for witness in parsed_reveal.wit.vtxinwit:
            assert_equal(len(witness.scriptWitness.stack), 2)
            assert (
                len(witness.scriptWitness.stack[0])
                <= MAX_NON_SCRIPT_WITNESS_ITEM_BYTES
            )
            witness_size = len(witness.serialize())
            witness_sizes.append(witness_size)
            assert witness_size <= MAX_DEFAULT_WITNESS_BYTES
        self.log.info(
            f"Complete serialized carrier witnesses are {min(witness_sizes)}.."
            f"{max(witness_sizes)} bytes (default ceiling {MAX_DEFAULT_WITNESS_BYTES})"
        )
        self.log.info(
            f"Reveal serialization={reveal_size} bytes, weight={reveal_weight}, "
            f"vsize={parsed_reveal.get_vsize()}"
        )

        # A damaged signature must fail before the exact same authenticated
        # transaction is offered.  This demonstrates that the data script is
        # not anyone-can-spend.
        damaged = tx_from_hex(reveal_hex)
        damaged_sig = bytearray(damaged.wit.vtxinwit[0].scriptWitness.stack[0])
        damaged_sig[10] ^= 1
        damaged.wit.vtxinwit[0].scriptWitness.stack[0] = bytes(damaged_sig)
        damaged_result = sender.testmempoolaccept([damaged.serialize().hex()])[0]
        assert_equal(damaged_result["allowed"], False)
        self.log.info(
            "Damaged carrier signature rejected: "
            f"{damaged_result['reject-reason']}"
        )

        acceptance = sender.testmempoolaccept([reveal_hex])[0]
        assert_equal(acceptance["allowed"], True)
        self.log.info(
            "RDTS/default-policy testmempoolaccept allowed DROPSTITCH reveal: "
            f"vsize={acceptance['vsize']}, fees={acceptance['fees']}"
        )

        reveal_txid = sender.sendrawtransaction(reveal_hex)
        self.wait_for_mempool(relay, reveal_txid)
        self.log.info(f"Default-policy peer relayed reveal {reveal_txid}")

        # Reconstruct exclusively from the signed transaction serialization,
        # including the manifest found in its wire-decoded OP_RETURN output.
        parsed_wire = tx_from_hex(reveal_hex)
        wire_witnesses = [
            witness.scriptWitness.stack
            for witness in parsed_wire.wit.vtxinwit
        ]
        decoded_rpc = sender.decoderawtransaction(reveal_hex)
        manifest_from_wire = extract_single_op_return(decoded_rpc)
        assert_equal(manifest_from_wire, manifest_from_funding)
        recovered = decode_committed_witnesses(
            manifest_from_funding,
            manifest_from_wire,
            wire_witnesses,
            expected_pubkey=pubkey,
        )
        assert_equal(recovered, content)
        assert_equal(hashlib.sha256(recovered).digest(), manifest.content_sha256)
        assert_equal(parse_manifest(manifest_from_wire).mime, mime)
        self.log.info(
            f"Wire content ({mime}) reconstructed byte-for-byte and SHA256-verified"
        )

        self.generate(sender, 1)
        if reveal_txid in sender.getrawmempool():
            # Knots' compiled block-template size default (300 kB) is stricter
            # than its 400 kWU standard-transaction relay ceiling.  A large
            # stress reveal can therefore relay normally but wait in the
            # mempool. Include that already-accepted tx explicitly to prove
            # block consensus independently of local template selection.
            self.log.info(
                "Default block template left the relay-standard reveal in the "
                "mempool; explicitly mining it to prove consensus acceptance"
            )
            self.generateblock(
                sender,
                sender.getnewaddress(address_type="bech32m"),
                [reveal_txid],
            )
        assert reveal_txid not in sender.getrawmempool()
        for txid, vout in carrier_outpoints:
            assert_equal(sender.gettxout(txid, vout), None)
        pointer_coin = sender.gettxout(reveal_txid, manifest.pointer_vout)
        assert pointer_coin is not None
        assert pointer_coin["confirmations"] >= 1
        assert_equal(pointer_coin["scriptPubKey"]["address"], pointer_address)
        assert_equal(pointer_coin["scriptPubKey"]["type"], "witness_v1_taproot")
        assert_equal(sender.gettxout(reveal_txid, 1), None)
        self.log.info(
            "All temporary P2WSH carriers are consumed; only the ordinary "
            "P2TR pointer remains"
        )

        cleanup_address = sender.getnewaddress(address_type="bech32m")
        cleanup_unsigned = sender.createrawtransaction(
            [{"txid": reveal_txid, "vout": manifest.pointer_vout}],
            [
                {
                    cleanup_address: pointer_coin["value"]
                    - Decimal(CLEANUP_FEE_SATS) / COIN
                }
            ],
        )
        cleanup_signed = sender.signrawtransactionwithwallet(cleanup_unsigned)
        assert_equal(cleanup_signed["complete"], True)
        cleanup_acceptance = sender.testmempoolaccept([cleanup_signed["hex"]])[0]
        assert_equal(cleanup_acceptance["allowed"], True)
        cleanup_txid = sender.sendrawtransaction(cleanup_signed["hex"])
        self.wait_for_mempool(relay, cleanup_txid)
        self.generate(sender, 1)
        assert_equal(sender.gettxout(reveal_txid, manifest.pointer_vout), None)
        cleanup_vout = self.vout_for_address(
            sender.decoderawtransaction(cleanup_signed["hex"]), cleanup_address
        )
        assert sender.gettxout(cleanup_txid, cleanup_vout) is not None
        self.log.info(f"Spendable P2TR pointer swept successfully in {cleanup_txid}")


if __name__ == "__main__":
    DropstitchRegtest(__file__).main()
