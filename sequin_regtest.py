#!/usr/bin/env python3
"""End-to-end SEQUIN proof on two default-policy, RDTS-active Knots nodes."""

from __future__ import annotations

from decimal import Decimal
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

from test_framework.address import address_to_scriptpubkey, script_to_p2wsh  # noqa: E402
from test_framework.messages import (  # noqa: E402
    COIN,
    COutPoint,
    CTransaction,
    CTxIn,
    CTxInWitness,
    CTxOut,
    tx_from_hex,
)
from test_framework.script import CScript, OP_DROP, OP_TRUE  # noqa: E402
from test_framework.test_framework import BitcoinTestFramework  # noqa: E402
from test_framework.util import assert_equal  # noqa: E402

from sequin import (  # noqa: E402
    build_manifest,
    decode_content,
    encode_sequences,
    extract_op_return_payload,
    parse_manifest,
)


BLAKE2B_ALWAYS_ACTIVE = "-testactivationheight=blake2b@1"
RDTS_FUTURE_EXPIRY = "-rdtsexpiry=2000000000"
FANOUT_VALUE = Decimal("0.00100000")
CLEANUP_FEE = Decimal("0.00010000")

# A real, self-contained SVG payload rather than a string-only toy message.
NFT = b"""<svg xmlns="http://www.w3.org/2000/svg" width="320" height="320" viewBox="0 0 320 320">
<defs><radialGradient id="g"><stop stop-color="#ffe66d"/><stop offset="1" stop-color="#ff4d8d"/></radialGradient></defs>
<rect width="320" height="320" rx="48" fill="#161629"/><circle cx="160" cy="145" r="105" fill="url(#g)"/>
<path d="M92 151q68-92 136 0q-68 92-136 0" fill="none" stroke="#161629" stroke-width="15"/>
<text x="160" y="284" text-anchor="middle" font-family="monospace" font-size="28" fill="white">SEQUIN #1</text></svg>"""


class SequinRegtest(BitcoinTestFramework):
    def add_options(self, parser):
        self.add_wallet_options(parser, descriptors=True, legacy=False)
        parser.add_argument(
            "--stress-inputs",
            type=int,
            default=0,
            help="replace the SVG with deterministic bytes requiring exactly N inputs",
        )

    def set_test_params(self):
        self.num_nodes = 2
        self.setup_clean_chain = True
        # This changes only regtest deployment timing. All relay-policy knobs
        # (-datacarrier*, -acceptnonstddatacarrier, -corepolicy, etc.) remain at
        # the compiled Bitcoin Knots defaults on both nodes.
        self.extra_args = [
            [BLAKE2B_ALWAYS_ACTIVE, RDTS_FUTURE_EXPIRY, "-corepolicy=0"],
            [BLAKE2B_ALWAYS_ACTIVE, RDTS_FUTURE_EXPIRY, "-corepolicy=0"],
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

    def assert_knots_policy_negative_control(self, sender, relay):
        """Show OP_DROP data is consensus-valid but rejected from the mempool."""
        witness_script = CScript([b"SEQUIN negative control", OP_DROP, OP_TRUE])
        control_address = script_to_p2wsh(witness_script)
        funding = sender.send(outputs=[{control_address: FANOUT_VALUE}])
        assert_equal(funding["complete"], True)
        self.wait_for_mempool(relay, funding["txid"])
        funding_hex = sender.gettransaction(funding["txid"])["hex"]
        control_vout = self.vout_for_address(
            sender.decoderawtransaction(funding_hex), control_address
        )
        self.generate(sender, 1)

        cleanup_address = sender.getnewaddress(address_type="bech32m")
        spend = CTransaction()
        spend.version = 1
        spend.nLockTime = 0
        spend.vin = [CTxIn(COutPoint(int(funding["txid"], 16), control_vout))]
        spend.vout = [CTxOut(
            int((FANOUT_VALUE - CLEANUP_FEE) * COIN),
            address_to_scriptpubkey(cleanup_address),
        )]
        spend.wit.vtxinwit = [CTxInWitness()]
        spend.wit.vtxinwit[0].scriptWitness.stack = [bytes(witness_script)]
        spend.rehash()

        rejection = sender.testmempoolaccept([spend.serialize().hex()])[0]
        assert_equal(rejection["allowed"], False)
        assert_equal(rejection["reject-reason"], "txn-datacarrier-nonstandard")
        self.log.info("Negative control rejected as txn-datacarrier-nonstandard")

        # Policy is intentionally bypassed by a miner here. Acceptance of the
        # resulting block proves the same transaction is RDTS consensus-valid,
        # and consumes the control UTXO so the test leaves no junk behind.
        self.generateblock(
            sender,
            sender.getnewaddress(address_type="bech32m"),
            [spend.serialize().hex()],
        )
        assert_equal(sender.gettxout(funding["txid"], control_vout), None)
        assert sender.gettxout(spend.hash, 0) is not None
        self.log.info("RDTS accepted the negative control in a block; its UTXO was swept")

    def run_test(self):
        sender, relay = self.nodes

        info = sender.getdeploymentinfo()
        assert_equal(info["blake2b"], {"height": 1, "active": True})
        deployment = info["deployments"]["reduced_data"]
        assert_equal(deployment["type"], "flagday")
        assert_equal(deployment["height"], 1)
        assert_equal(deployment["expiry_time"], 2_000_000_000)
        assert_equal(deployment["active"], True)
        self.log.info("RDTS is active; both nodes retain untouched Knots relay defaults")

        self.generate(sender, 101)
        self.assert_knots_policy_negative_control(sender, relay)

        if self.options.stress_inputs:
            assert 1 <= self.options.stress_inputs <= 0xFFFF
            content = bytes(range(256)) * ((self.options.stress_inputs * 4 + 255) // 256)
            content = content[:self.options.stress_inputs * 4]
            mime = "application/octet-stream"
        else:
            content = NFT
            mime = "image/svg+xml"

        sequences = encode_sequences(content)
        manifest_bytes = build_manifest(content, mime, pointer_vout=0)
        manifest = parse_manifest(manifest_bytes)
        assert_equal(manifest.input_count, len(sequences))
        assert len(manifest_bytes) <= 80
        self.log.info(
            f"Encoding {len(content)} bytes into {len(sequences)} ordinary inputs; "
            f"manifest={len(manifest_bytes)} bytes"
        )

        # Fan out to unique, wallet-controlled P2TR outputs. These are all
        # normal spendable outputs, not data-shaped or burn outputs.
        carrier_addresses = [
            sender.getnewaddress(address_type="bech32m") for _ in sequences
        ]
        targets = [{address: FANOUT_VALUE} for address in carrier_addresses]
        fanout = sender.send(outputs=targets)
        assert_equal(fanout["complete"], True)
        fanout_txid = fanout["txid"]
        self.wait_for_mempool(relay, fanout_txid)
        self.log.info(f"Default-policy peer relayed fanout {fanout_txid}")
        fanout_hex = sender.gettransaction(fanout_txid)["hex"]
        decoded_fanout = sender.decoderawtransaction(fanout_hex)
        self.generate(sender, 1)

        carrier_inputs = []
        carrier_outpoints = []
        address_to_vout = {
            output["scriptPubKey"].get("address"): output["n"]
            for output in decoded_fanout["vout"]
        }
        for address, sequence in zip(carrier_addresses, sequences):
            vout = address_to_vout[address]
            carrier_inputs.append(
                {"txid": fanout_txid, "vout": vout, "sequence": sequence}
            )
            carrier_outpoints.append((fanout_txid, vout))

            coin = sender.gettxout(fanout_txid, vout)
            assert coin is not None
            assert_equal(coin["scriptPubKey"]["type"], "witness_v1_taproot")

        pointer_address = sender.getnewaddress(address_type="bech32m")
        reveal_fee = Decimal(max(50_000, len(carrier_inputs) * 150)) / COIN
        pointer_value = FANOUT_VALUE * len(carrier_inputs) - reveal_fee
        reveal_unsigned = sender.createrawtransaction(
            carrier_inputs,
            [{pointer_address: pointer_value}, {"data": manifest_bytes.hex()}],
            0,
        )
        reveal_tx = tx_from_hex(reveal_unsigned)
        reveal_tx.version = 1
        reveal_tx.nLockTime = 0
        reveal_signed = sender.signrawtransactionwithwallet(reveal_tx.serialize().hex())
        assert_equal(reveal_signed["complete"], True)

        acceptance = sender.testmempoolaccept([reveal_signed["hex"]])[0]
        assert_equal(acceptance["allowed"], True)
        self.log.info(
            f"RDTS/default-policy testmempoolaccept allowed reveal: "
            f"vsize={acceptance['vsize']}, fees={acceptance['fees']}"
        )

        reveal_txid = sender.sendrawtransaction(reveal_signed["hex"])
        self.wait_for_mempool(relay, reveal_txid)
        self.log.info(f"Default-policy peer relayed reveal {reveal_txid}")

        # Decode from the signed network serialization, not from pre-signing
        # objects. This proves input order and exact uint32 sequences survive.
        parsed_reveal = tx_from_hex(reveal_signed["hex"])
        assert_equal(parsed_reveal.version, 1)
        assert_equal(parsed_reveal.nLockTime, 0)
        wire_sequences = [txin.nSequence for txin in parsed_reveal.vin]
        decoded_rpc = sender.decoderawtransaction(reveal_signed["hex"])
        null_data_outputs = [
            output
            for output in decoded_rpc["vout"]
            if output["scriptPubKey"]["type"] == "nulldata"
        ]
        assert_equal(len(null_data_outputs), 1)
        manifest_from_wire = extract_op_return_payload(
            bytes.fromhex(null_data_outputs[0]["scriptPubKey"]["hex"])
        )
        recovered = decode_content(manifest_from_wire, wire_sequences)
        assert_equal(recovered, content)
        self.log.info("Recovered payload is byte-for-byte identical and SHA256-verified")

        self.generate(sender, 1)
        for txid, vout in carrier_outpoints:
            assert_equal(sender.gettxout(txid, vout), None)
        pointer_coin = sender.gettxout(reveal_txid, manifest.pointer_vout)
        assert pointer_coin is not None
        assert_equal(pointer_coin["scriptPubKey"]["address"], pointer_address)
        assert_equal(pointer_coin["scriptPubKey"]["type"], "witness_v1_taproot")
        self.log.info("All fanout UTXOs are gone; one ordinary consolidation UTXO remains")

        # Spend the pointer as a final proof that the consolidation output is
        # wallet-controlled and not an accidental data burn.
        cleanup_address = sender.getnewaddress(address_type="bech32m")
        cleanup_unsigned = sender.createrawtransaction(
            [{"txid": reveal_txid, "vout": manifest.pointer_vout}],
            [{cleanup_address: pointer_coin["value"] - CLEANUP_FEE}],
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
        self.log.info(f"Spendable pointer swept successfully in {cleanup_txid}")


if __name__ == "__main__":
    SequinRegtest(__file__).main()
