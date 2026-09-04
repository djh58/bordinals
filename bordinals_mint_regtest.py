#!/usr/bin/env python3
"""End-to-end guarded minter proof on two default-policy Knots nodes."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import time


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

from test_framework.test_framework import BitcoinTestFramework  # noqa: E402
from test_framework.util import assert_equal  # noqa: E402

from bordinals import decode_committed_witnesses  # noqa: E402
from bordinals_mint import (  # noqa: E402
    parse_transaction,
)


BLAKE2B_ALWAYS_ACTIVE = "-testactivationheight=blake2b@1"
RDTS_FUTURE_EXPIRY = "-rdtsexpiry=2000000000"


def consent_record(
    address: str, content: bytes, *, label: str, ttl_seconds: int = 24 * 60 * 60
) -> dict:
    now = datetime.now(timezone.utc).replace(microsecond=0)
    return {
        "address": address,
        "gift_sats": 2_000,
        "label": label,
        "consent": {
            "mode": "reference",
            "reference": f"regtest:{label}",
            "obtained_at": now.isoformat().replace("+00:00", "Z"),
            "expires_at": (now + timedelta(seconds=ttl_seconds)).isoformat().replace(
                "+00:00", "Z"
            ),
        },
    }


class BordinalsMintRegtest(BitcoinTestFramework):
    def add_options(self, parser):
        self.add_wallet_options(parser, descriptors=True, legacy=False)

    def set_test_params(self):
        self.num_nodes = 2
        self.setup_clean_chain = True
        self.extra_args = [
            [BLAKE2B_ALWAYS_ACTIVE, RDTS_FUTURE_EXPIRY, "-corepolicy=0"],
            [BLAKE2B_ALWAYS_ACTIVE, RDTS_FUTURE_EXPIRY, "-corepolicy=0"],
        ]

    def skip_test_if_missing_module(self):
        self.skip_if_no_wallet()

    def wait_for_mempool(self, node, txid):
        self.wait_until(lambda: txid in node.getrawmempool())

    def run_minter_cli(self, *arguments):
        result = subprocess.run(
            [sys.executable, str(HERE / "bordinals_mint.py"), *arguments],
            capture_output=True,
            text=True,
            check=False,
            timeout=180,
        )
        if result.returncode:
            raise AssertionError(
                f"minter CLI failed ({result.returncode}):\n{result.stdout}\n{result.stderr}"
            )
        return json.loads(result.stdout)

    def run_test(self):
        sender, receiver = self.nodes
        sender.createwallet(wallet_name="funding-source", descriptors=True)
        source_wallet = sender.get_wallet_rpc("funding-source")
        mining_address = source_wallet.getnewaddress(address_type="bech32")
        self.generatetoaddress(sender, 101, mining_address)
        sender.createwallet(wallet_name="bordinals-minter", descriptors=True)
        minter_wallet = sender.get_wallet_rpc("bordinals-minter")
        # Give the minter wallet only a confirmed P2TR coin. This exercises the
        # 65-byte Schnorr ALL|UNIFIED funding-signature path rather than only
        # the legacy ECDSA witness path.
        minter_funding_address = minter_wallet.getnewaddress(address_type="bech32m")
        source_wallet.sendtoaddress(minter_funding_address, 5)
        self.generatetoaddress(sender, 1, mining_address)
        content = (
            b'<svg xmlns="http://www.w3.org/2000/svg" width="120" height="80">'
            b'<rect width="120" height="80" fill="#111827"/>'
            b"<desc>" + b"BORDINALS-MULTI-INPUT-" * 150 + b"</desc>"
            b'<text x="60" y="48" text-anchor="middle" fill="#fbbf24">BORD</text>'
            b"</svg>"
        )
        assert len(content) > 3_000
        recipient_address = receiver.getnewaddress(address_type="bech32m")
        recipient = consent_record(recipient_address, content, label="delivery")

        before_mempools = [node.getrawmempool() for node in self.nodes]
        artifact_path = Path(self.options.tmpdir) / "regtest.svg"
        recipients_path = Path(self.options.tmpdir) / "recipients.json"
        plan_path = Path(self.options.tmpdir) / "bordinals-plan.json"
        artifact_path.write_bytes(content)
        recipients_path.write_text(
            json.dumps(
                {
                    "schema": "bordinals-consent/1",
                    "chain": "regtest",
                    "artifact_blake2b256": hashlib.blake2b(
                        content, digest_size=32
                    ).hexdigest(),
                    "entries": [recipient],
                }
            ),
            encoding="utf-8",
        )
        prepare_arguments = (
            "prepare",
            str(artifact_path),
            "--mime",
            "image/svg+xml",
            "--recipients",
            str(recipients_path),
            "--plan-out",
            str(plan_path),
            "--chain",
            "regtest",
            "--fee-rate-sat-vb",
            "1",
            "--wallet",
            "bordinals-minter",
            "--bitcoin-cli",
            self.options.bitcoincli,
            "--datadir",
            str(sender.datadir_path),
            "--acknowledge-recipient-consent",
            "I CONFIRM EVERY RECIPIENT OPTED IN",
        )
        preview = self.run_minter_cli(*prepare_arguments)
        assert_equal(preview["status"], "validated-read-only")
        assert not plan_path.exists()
        assert_equal([node.getrawmempool() for node in self.nodes], before_mempools)

        prepared = self.run_minter_cli(*prepare_arguments, "--execute")
        assert_equal(prepared["status"], "prepared-not-broadcast")
        assert_equal(plan_path.stat().st_mode & 0o777, 0o600)
        plan = json.loads(plan_path.read_text(encoding="utf-8"))
        assert_equal([node.getrawmempool() for node in self.nodes], before_mempools)
        entry = plan["entries"][0]
        expected_locks = {
            (item["txid"], item["vout"])
            for item in entry["funding"]["locked_wallet_inputs"]
        }
        assert_equal(
            {
                (item["txid"], item["vout"])
                for item in minter_wallet.listlockunspent()
            },
            expected_locks,
        )
        self.restart_node(0)
        if "bordinals-minter" not in sender.listwallets():
            sender.loadwallet("bordinals-minter")
        minter_wallet = sender.get_wallet_rpc("bordinals-minter")
        assert_equal(
            {
                (item["txid"], item["vout"])
                for item in minter_wallet.listlockunspent()
            },
            expected_locks,
        )
        self.connect_nodes(0, 1)
        self.log.info(
            "Dry-run stayed inert; signed plan locks survived a full node restart"
        )

        funding_result = self.run_minter_cli(
            "broadcast",
            str(plan_path),
            "--stage",
            "funding",
            "--entry",
            "0",
            "--bitcoin-cli",
            self.options.bitcoincli,
            "--datadir",
            str(sender.datadir_path),
            "--execute",
        )
        assert_equal(funding_result[0]["txid"], entry["funding"]["txid"])
        self.wait_for_mempool(receiver, entry["funding"]["txid"])
        self.generate(sender, 1)

        reveal_result = self.run_minter_cli(
            "broadcast",
            str(plan_path),
            "--stage",
            "reveal",
            "--entry",
            "0",
            "--bitcoin-cli",
            self.options.bitcoincli,
            "--datadir",
            str(sender.datadir_path),
            "--execute",
        )
        assert_equal(reveal_result[0]["txid"], entry["reveal"]["txid"])
        self.wait_for_mempool(receiver, entry["reveal"]["txid"])
        reveal = parse_transaction(entry["reveal"]["hex"])
        manifest = bytes.fromhex(entry["manifest_hex"])
        assert_equal(
            decode_committed_witnesses(
                manifest, manifest, [txin.witness for txin in reveal.inputs]
            ),
            content,
        )
        assert_equal(reveal.outputs[0].value_sats, recipient["gift_sats"])
        assert_equal(reveal.outputs[0].script_pubkey.hex(), entry["recipient_script_pubkey"])
        self.generate(sender, 1)
        pointer = receiver.gettxout(entry["reveal"]["txid"], 0)
        assert pointer is not None
        assert_equal(int(pointer["value"] * 100_000_000), recipient["gift_sats"])
        self.log.info("Reveal relayed, reconstructed, and delivered a spendable P2TR UTXO")

        # Exercise the persisted, mutually exclusive emergency path on a second
        # independent job. It returns every carrier to a wallet-owned P2TR output.
        refund_recipient_address = receiver.getnewaddress(address_type="bech32m")
        refund_content = (
            b"<svg xmlns='http://www.w3.org/2000/svg'><desc>"
            + b"REFUND-MULTI-INPUT-" * 170
            + b"</desc><text>refund</text></svg>"
        )
        refund_recipient = consent_record(
            refund_recipient_address,
            refund_content,
            label="refund",
            ttl_seconds=15,
        )
        refund_artifact_path = Path(self.options.tmpdir) / "refund.svg"
        refund_recipients_path = Path(self.options.tmpdir) / "refund-recipients.json"
        refund_plan_path = Path(self.options.tmpdir) / "refund-plan.json"
        refund_artifact_path.write_bytes(refund_content)
        refund_recipients_path.write_text(
            json.dumps(
                {
                    "schema": "bordinals-consent/1",
                    "chain": "regtest",
                    "artifact_blake2b256": hashlib.blake2b(
                        refund_content, digest_size=32
                    ).hexdigest(),
                    "entries": [refund_recipient],
                }
            ),
            encoding="utf-8",
        )
        self.run_minter_cli(
            "prepare",
            str(refund_artifact_path),
            "--mime",
            "image/svg+xml",
            "--recipients",
            str(refund_recipients_path),
            "--plan-out",
            str(refund_plan_path),
            "--chain",
            "regtest",
            "--fee-rate-sat-vb",
            "1",
            "--wallet",
            "bordinals-minter",
            "--bitcoin-cli",
            self.options.bitcoincli,
            "--datadir",
            str(sender.datadir_path),
            "--acknowledge-recipient-consent",
            "I CONFIRM EVERY RECIPIENT OPTED IN",
            "--execute",
        )
        refund_plan = json.loads(refund_plan_path.read_text(encoding="utf-8"))
        refund_entry = refund_plan["entries"][0]
        self.run_minter_cli(
            "broadcast",
            str(refund_plan_path),
            "--stage",
            "funding",
            "--entry",
            "0",
            "--bitcoin-cli",
            self.options.bitcoincli,
            "--datadir",
            str(sender.datadir_path),
            "--execute",
        )
        self.wait_for_mempool(receiver, refund_entry["funding"]["txid"])
        self.generate(sender, 1)
        expiry = datetime.fromisoformat(
            refund_recipient["consent"]["expires_at"][:-1] + "+00:00"
        )
        wait_seconds = (expiry - datetime.now(timezone.utc)).total_seconds()
        if wait_seconds >= 0:
            time.sleep(wait_seconds + 1)
        sender.unloadwallet("bordinals-minter")
        refund_result = self.run_minter_cli(
            "broadcast",
            str(refund_plan_path),
            "--stage",
            "refund",
            "--entry",
            "0",
            "--bitcoin-cli",
            self.options.bitcoincli,
            "--datadir",
            str(sender.datadir_path),
            "--acknowledge-refund",
            "I CHOOSE REFUND INSTEAD OF THE RECIPIENT DELIVERY",
            "--execute",
        )
        assert_equal(refund_result[0]["txid"], refund_entry["refund"]["txid"])
        self.wait_for_mempool(receiver, refund_entry["refund"]["txid"])
        refund = parse_transaction(refund_entry["refund"]["hex"])
        assert_equal(len(refund.outputs), 1)
        assert_equal(refund.outputs[0].value_sats, refund_entry["refund"]["value_sats"])
        self.generate(sender, 1)
        assert sender.gettxout(refund_entry["refund"]["txid"], 0) is not None
        self.log.info(
            "Expired-consent refund relayed without a loaded wallet and recovered value"
        )


if __name__ == "__main__":
    BordinalsMintRegtest(__file__).main()
