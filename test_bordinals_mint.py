#!/usr/bin/env python3
"""Pure-Python tests for BORDINALS transaction planning primitives."""

from __future__ import annotations

import copy
from contextlib import redirect_stdout
from datetime import datetime, timezone
from decimal import Decimal
import hashlib
import io
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from bordinals import (
    BORDINALS_SIGHASH,
    build_manifest,
    build_script,
    encode_payloads,
    op_return_script,
    p2wsh_scriptpubkey,
)
from bordinals_mint import (
    BROADCAST_ACK,
    BitcoinCliRPC,
    ExecutionJournal,
    FORMAT,
    JOURNAL_FORMAT,
    KnotsRPCError,
    LockCleanupError,
    MAINNET_GENESIS,
    REFUND_ACK,
    REGTEST_GENESIS,
    SCHEMA_VERSION,
    UNLOCK_ACK,
    MintError,
    ReadOnlyRPC,
    Transaction,
    TxInput,
    TxOutput,
    _cleanup_reserved_after_failure,
    _funding_signature_types_are_unified,
    _unlock_exact_wallet_inputs,
    broadcast_plan_stage,
    compact_size,
    compressed_pubkey,
    counterparty_collision,
    execution_journal_path,
    load_consent_records,
    locked_plan,
    main,
    parse_fee_rate,
    parse_transaction,
    plan_status,
    p2wsh_address,
    preview_preparation,
    rc4,
    seal_plan,
    sign_carrier_transaction,
    sign_ecdsa_low_s,
    tx_with_placeholder_witnesses,
    unified_witness_v0_sighash,
    unlock_plan_inputs,
    verify_ecdsa,
    verify_plan,
    write_new_private_json,
)


class RecordingRPC:
    def __init__(self) -> None:
        self.calls: list[tuple[str, tuple[object, ...]]] = []

    def call(self, method: str, *params: object) -> object:
        self.calls.append((method, params))
        raise AssertionError(f"unexpected RPC call: {method}")


def valid_plan(*, chain: str = "regtest") -> dict[str, object]:
    """Build one complete, internally valid plan without an RPC or wallet."""
    content = b"<svg xmlns='http://www.w3.org/2000/svg'><text>BORD</text></svg>"
    mime = "image/svg+xml"
    manifest = build_manifest(content, mime)
    secret = 1
    pubkey = compressed_pubkey(secret)
    scripts = [
        build_script(payload, pubkey, carrier_index=index)
        for index, payload in enumerate(encode_payloads(content))
    ]
    self_signature = sign_ecdsa_low_s(secret, b"\x42" * 32) + bytes(
        (BORDINALS_SIGHASH,)
    )
    funding_input = TxInput(bytes.fromhex("11" * 32), 3)
    funding_input.witness = [self_signature, pubkey]
    carrier_values = [10_000 for _ in scripts]
    recipient_script = b"\x51\x20" + bytes.fromhex("22" * 32)
    change_script = b"\x51\x20" + bytes.fromhex("33" * 32)
    funding = Transaction(
        2,
        [funding_input],
        [
            *[
                TxOutput(value, p2wsh_scriptpubkey(script))
                for value, script in zip(carrier_values, scripts, strict=True)
            ],
            TxOutput(0, op_return_script(manifest)),
            TxOutput(50_000, change_script),
        ],
    )
    carrier_vouts = list(range(len(scripts)))
    spent = [funding.outputs[index] for index in carrier_vouts]
    reveal = sign_carrier_transaction(
        Transaction(
            2,
            [
                TxInput(bytes.fromhex(funding.txid)[::-1], index)
                for index in carrier_vouts
            ],
            [
                TxOutput(8_000 * len(scripts), recipient_script),
                TxOutput(0, op_return_script(manifest)),
            ],
        ),
        spent,
        scripts,
        secret,
    )
    reveal_fee = sum(carrier_values) - 8_000 * len(scripts)
    refund_script = b"\x51\x20" + bytes.fromhex("44" * 32)
    refund_value = sum(carrier_values) - 2_500
    refund = sign_carrier_transaction(
        Transaction(
            2,
            [
                TxInput(bytes.fromhex(funding.txid)[::-1], index)
                for index in carrier_vouts
            ],
            [TxOutput(refund_value, refund_script)],
        ),
        spent,
        scripts,
        secret,
    )
    consent = {
        "mode": "reference",
        "reference": "consent:test-fixture",
        "obtained_at": "2026-09-01T00:00:00Z",
        "expires_at": "2030-09-01T00:00:00Z",
    }
    funding_fee = 500
    entry = {
        "index": 0,
        "recipient": {
            "address": "bcrt1ptestrecipient",
            "gift_sats": 8_000 * len(scripts),
            "label": "fixture",
            "consent": consent,
        },
        "recipient_script_pubkey": recipient_script.hex(),
        "carrier_pubkey": pubkey.hex(),
        "carrier_count": len(scripts),
        "carrier_vouts": carrier_vouts,
        "carrier_values_sats": carrier_values,
        "manifest_hex": manifest.hex(),
        "funding": {
            "hex": funding.serialize().hex(),
            "txid": funding.txid,
            "wtxid": funding.wtxid,
            "fee_sats": funding_fee,
            "weight": funding.weight,
            "vsize": funding.vsize,
            "locked_wallet_inputs": [
                {"txid": funding.inputs[0].prev_txid, "vout": 3}
            ],
            "change": {
                "vout": len(scripts) + 1,
                "address": "bcrt1ptestchange",
                "script_pubkey": change_script.hex(),
                "value_sats": 50_000,
            },
        },
        "reveal": {
            "hex": reveal.serialize().hex(),
            "txid": reveal.txid,
            "wtxid": reveal.wtxid,
            "fee_sats": reveal_fee,
            "weight": reveal.weight,
            "vsize": reveal.vsize,
            "pointer_vout": 0,
            "preflight": [],
        },
        "refund": {
            "hex": refund.serialize().hex(),
            "txid": refund.txid,
            "wtxid": refund.wtxid,
            "fee_sats": 2_500,
            "weight": refund.weight,
            "vsize": refund.vsize,
            "address": "bcrt1ptestrefund",
            "script_pubkey": refund_script.hex(),
            "value_sats": refund_value,
            "preflight": [],
        },
    }
    total_fee = funding_fee + reveal_fee
    genesis = MAINNET_GENESIS if chain == "main" else REGTEST_GENESIS
    return seal_plan(
        {
            "format": FORMAT,
            "schema_version": SCHEMA_VERSION,
            "plan_id": "55" * 16,
            "created_at": "2026-09-03T00:00:00Z",
            "state": "PREPARED_NOT_BROADCAST",
            "reservation": {
                "id": "66" * 16,
                "wallet_name": "fixture-wallet",
                "journal_format": JOURNAL_FORMAT,
            },
            "chain_snapshot": {"chain": chain, "genesis": genesis},
            "artifact": {
                "name": "fixture.svg",
                "mime": mime,
                "length": len(content),
                "blake2b256": hashlib.blake2b(content, digest_size=32).hexdigest(),
                "carrier_count": len(scripts),
            },
            "policy": {
                "consent": "recorded-not-cryptographically-verified",
                "fee_rate_sat_vb": "1",
                "max_fee_rate_sat_vb": "10",
                "max_carriers": 177,
                "max_funding_fee_sats_each": 100_000,
                "max_reveal_fee_sats_each": 1_000_000,
                "max_total_fee_sats": 5_000_000,
                "max_total_spend_sats": 5_000_000,
                "maxfeerate_rpc_btc_kvb": "0.0001",
                "requires_funding_confirmations": 1,
            },
            "totals": {
                "recipients": 1,
                "gift_sats": entry["recipient"]["gift_sats"],
                "normal_path_fee_sats": total_fee,
                "normal_path_spend_sats": entry["recipient"]["gift_sats"] + total_fee,
                "temporarily_locked_carrier_sats": sum(carrier_values),
            },
            "entries": [entry],
        }
    )


def create_valid_journal(path: Path, plan: dict[str, object]) -> ExecutionJournal:
    journal = ExecutionJournal.create(
        path,
        reservation_id=plan["reservation"]["id"],
        chain=plan["chain_snapshot"]["chain"],
        genesis=plan["chain_snapshot"]["genesis"],
        wallet_name=plan["reservation"]["wallet_name"],
    )
    for entry in plan["entries"]:
        inputs = entry["funding"]["locked_wallet_inputs"]
        journal.record_inputs_selected(entry["index"], inputs)
        journal.record_locks_persisted(entry["index"], inputs)
    journal.commit_plan(plan)
    return journal


class PlanRPC:
    """State-aware fake implementing only read-only Knots RPC shapes we use."""

    def __init__(self, plan: dict[str, object]) -> None:
        self.plan = plan
        self.calls: list[tuple[str, tuple[object, ...]]] = []
        self.mempool: set[str] = set()
        self.raw_known: set[str] = set()
        self.utxos: dict[tuple[str, int], dict[str, object]] = {}
        self.locks = {
            (item["txid"], item["vout"])
            for item in plan["entries"][0]["funding"]["locked_wallet_inputs"]
        }

    def add_funding_carriers(self, confirmations: int = 1) -> None:
        entry = self.plan["entries"][0]
        funding = parse_transaction(entry["funding"]["hex"])
        for vout in entry["carrier_vouts"]:
            output = funding.outputs[vout]
            self.utxos[(funding.txid, vout)] = {
                "value": Decimal(output.value_sats) / Decimal(100_000_000),
                "scriptPubKey": {"hex": output.script_pubkey.hex()},
                "confirmations": confirmations,
            }

    def add_stage_output(self, stage: str, confirmations: int = 1) -> None:
        entry = self.plan["entries"][0]
        record = entry[stage]
        transaction = parse_transaction(record["hex"])
        vout = record.get("pointer_vout", 0) if stage == "reveal" else 0
        output = transaction.outputs[vout]
        self.utxos[(record["txid"], vout)] = {
            "value": Decimal(output.value_sats) / Decimal(100_000_000),
            "scriptPubKey": {"hex": output.script_pubkey.hex()},
            "confirmations": confirmations,
        }

    def call(self, method: str, *params: object) -> object:
        self.calls.append((method, params))
        entry = self.plan["entries"][0]
        chain = self.plan["chain_snapshot"]["chain"]
        if method == "getblockchaininfo":
            return {
                "chain": chain,
                "initialblockdownload": False,
                "blocks": 1_000_000 if chain == "main" else 101,
                "headers": 1_000_000 if chain == "main" else 101,
                "bestblockhash": "aa" * 32,
                "mediantime": 1_780_000_000,
            }
        if method == "getblockhash":
            if params[0] == 0:
                return self.plan["chain_snapshot"]["genesis"]
            return "0000000000000050c1e5f69672f459293be14f46e5a494e7a8c8541396f18eeb"
        if method == "getnetworkinfo":
            return {"version": 290401, "subversion": "/Knots:20260508/"}
        if method == "getdeploymentinfo":
            return {
                "blake2b": {"active": True, "height": 961_640},
                "deployments": {
                    "reduced_data": {
                        "active": True,
                        "height": 961_640,
                        "expiry_time": 1_819_756_800,
                    }
                },
            }
        if method == "getblockheader":
            return {"header_version": 2}
        if method == "getwalletinfo":
            return {
                "walletname": "fixture-wallet",
                "private_keys_enabled": True,
                "scanning": False,
            }
        if method == "validateaddress":
            address = params[0]
            script = (
                entry["refund"]["script_pubkey"]
                if address == entry["refund"]["address"]
                else entry["recipient_script_pubkey"]
            )
            return {
                "isvalid": True,
                "address": address,
                "witness_version": 1,
                "witness_program": script[4:],
                "scriptPubKey": script,
            }
        if method == "getaddressinfo":
            return {"ismine": True, "solvable": True, "iswatchonly": False}
        if method == "getmempoolinfo":
            return {"dustrelayfee": Decimal("0.00003")}
        if method == "getmempoolentry":
            if params[0] in self.mempool:
                for stage in ("funding", "reveal", "refund"):
                    if entry[stage]["txid"] == params[0]:
                        return {"vsize": 1, "wtxid": entry[stage]["wtxid"]}
            raise KnotsRPCError(method, "not in mempool", -5)
        if method == "getrawtransaction":
            txid = params[0]
            if txid in self.raw_known:
                for stage in ("funding", "reveal", "refund"):
                    if entry[stage]["txid"] == txid:
                        return entry[stage]["hex"]
            raise KnotsRPCError(method, "not found", -5)
        if method == "gettxout":
            return self.utxos.get((params[0], params[1]))
        if method == "testmempoolaccept":
            result = []
            fee_by_txid = {
                entry[name]["txid"]: entry[name]["fee_sats"]
                for name in ("funding", "reveal", "refund")
            }
            for raw in params[0]:
                transaction = parse_transaction(raw)
                result.append(
                    {
                        "txid": transaction.txid,
                        "wtxid": transaction.wtxid,
                        "allowed": True,
                        "vsize": transaction.vsize,
                        "fees": {
                            "base": Decimal(fee_by_txid[transaction.txid])
                            / Decimal(100_000_000)
                        },
                    }
                )
            return result
        if method == "sendrawtransaction":
            transaction = parse_transaction(params[0])
            self.mempool.add(transaction.txid)
            return transaction.txid
        if method == "listlockunspent":
            return [
                {"txid": txid, "vout": vout}
                for txid, vout in sorted(self.locks)
            ]
        if method == "lockunspent":
            unlock, outpoints = params[:2]
            keys = {(item["txid"], item["vout"]) for item in outpoints}
            if unlock:
                self.locks -= keys
            else:
                self.locks |= keys
            return True
        raise AssertionError(f"unexpected RPC call: {method}")


class UnlockFaultRPC(PlanRPC):
    """Fault-injection fake for exact wallet-lock cleanup."""

    def __init__(self, plan: dict[str, object], mode: str) -> None:
        super().__init__(plan)
        self.mode = mode

    def call(self, method: str, *params: object) -> object:
        if method == "lockunspent" and params[0] is True:
            self.calls.append((method, params))
            keys = {
                (item["txid"], item["vout"])
                for item in params[1]
            }
            if self.mode == "timeout-after-applied":
                self.locks -= keys
                raise KnotsRPCError(method, "response timed out", -28)
            if self.mode == "timeout-before-applied":
                raise KnotsRPCError(method, "node warming up", -28)
            if self.mode == "true-but-retained":
                return True
        return super().call(method, *params)


def vector_transaction() -> tuple[Transaction, list[TxOutput], bytes]:
    transaction = Transaction(
        2,
        [
            TxInput(bytes.fromhex("11" * 32), 3, sequence=0xFFFFFFFD),
            TxInput(bytes.fromhex("22" * 32), 7, sequence=0xFFFFFFFC),
        ],
        [
            TxOutput(123_456, b"\x51\x20" + bytes.fromhex("33" * 32)),
            TxOutput(0, b"\x6a\x04BORD"),
        ],
        42,
    )
    spent = [
        TxOutput(200_000, b"\x00\x20" + bytes.fromhex("44" * 32)),
        TxOutput(100_000, b"\x00\x20" + bytes.fromhex("55" * 32)),
    ]
    script = (
        b"\x01x\x75\x21"
        + bytes.fromhex(
            "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798"
        )
        + b"\xac"
    )
    return transaction, spent, script


class TransactionPrimitiveTest(unittest.TestCase):
    def test_compact_size_boundaries(self) -> None:
        self.assertEqual(compact_size(252), b"\xfc")
        self.assertEqual(compact_size(253), b"\xfd\xfd\x00")
        self.assertEqual(compact_size(65_535), b"\xfd\xff\xff")
        self.assertEqual(compact_size(65_536), b"\xfe\x00\x00\x01\x00")

    def test_transaction_round_trip_with_witness(self) -> None:
        transaction, _, _ = vector_transaction()
        transaction.inputs[0].witness = [b"signature", b"script"]
        transaction.inputs[1].witness = [b"x"]
        encoded = transaction.serialize().hex()
        decoded = parse_transaction(encoded)
        self.assertEqual(decoded.serialize().hex(), encoded)
        self.assertEqual(decoded.txid, transaction.txid)
        self.assertEqual(decoded.wtxid, transaction.wtxid)
        self.assertNotEqual(decoded.txid, decoded.wtxid)

    def test_rejects_unknown_witness_flag_and_superfluous_record(self) -> None:
        transaction, _, _ = vector_transaction()
        transaction.inputs[0].witness = [b"x"]
        encoded = bytearray(transaction.serialize())
        self.assertEqual(encoded[4:6], b"\x00\x01")
        encoded[5] = 2
        with self.assertRaisesRegex(MintError, "exactly 1"):
            parse_transaction(encoded.hex())

        txin = TxInput(bytes.fromhex("12" * 32), 0)
        output = TxOutput(1, b"\x51")
        superfluous = (
            b"\x02\x00\x00\x00\x00\x01\x01"
            + txin.serialize()
            + b"\x01"
            + output.serialize()
            + b"\x00"
            + b"\x00\x00\x00\x00"
        )
        with self.assertRaisesRegex(MintError, "superfluous"):
            parse_transaction(superfluous.hex())

    def test_rejects_noncanonical_compact_size(self) -> None:
        # Version followed by a non-canonical fd-encoded input count of one.
        malformed = "02000000fd0100"
        with self.assertRaisesRegex(MintError, "non-canonical CompactSize"):
            parse_transaction(malformed)

    def test_unified_sighash_matches_knots_v2941_vector(self) -> None:
        transaction, spent, script = vector_transaction()
        digest = unified_witness_v0_sighash(transaction, 1, script, spent)
        # Independently generated with Knots' test-framework
        # UnifiedSignatureHash(..., SigVersion::WITNESS_V0).
        self.assertEqual(
            digest.hex(),
            "8382a1f72ce88bd2fff0fa0846c177f1fcdeaefdeccb9369bdbef81956b868ae",
        )
        changed = Transaction(
            transaction.version,
            transaction.inputs,
            [*transaction.outputs[:-1], TxOutput(1, transaction.outputs[-1].script_pubkey)],
            transaction.locktime,
        )
        self.assertNotEqual(
            unified_witness_v0_sighash(changed, 1, script, spent), digest
        )

    def test_deterministic_low_s_signature_vector_and_verify(self) -> None:
        transaction, spent, script = vector_transaction()
        digest = unified_witness_v0_sighash(transaction, 1, script, spent)
        signature = sign_ecdsa_low_s(1, digest)
        self.assertEqual(
            signature.hex(),
            "304402201d8a50ce8ca5386e464ab74ce9cd7c65eafbfc9d32c3f5f6f8be117d3c85d9b5"
            "022056f281c624d568cfc03735ce8585d7224717e37c63c7f9304fd24cd456a3ea07",
        )
        pubkey = compressed_pubkey(1)
        self.assertTrue(verify_ecdsa(pubkey, digest, signature))
        damaged = digest[:-1] + bytes((digest[-1] ^ 1,))
        self.assertFalse(verify_ecdsa(pubkey, damaged, signature))

    def test_signs_exact_carrier_witnesses(self) -> None:
        secret = 1
        pubkey = compressed_pubkey(secret)
        content = b"signed carrier"
        scripts = [
            build_script(payload, pubkey, carrier_index=index)
            for index, payload in enumerate(encode_payloads(content))
        ]
        funding_id = bytes.fromhex("12" * 32)
        inputs = [TxInput(funding_id, index) for index in range(len(scripts))]
        spent = [
            TxOutput(10_000, b"\x00\x20" + hashlib.sha256(script).digest())
            for script in scripts
        ]
        transaction = Transaction(2, inputs, [TxOutput(9_000, b"\x51")])
        signed = sign_carrier_transaction(transaction, spent, scripts, secret)
        for index, txin in enumerate(signed.inputs):
            self.assertEqual(len(txin.witness), 2)
            self.assertEqual(txin.witness[0][-1], BORDINALS_SIGHASH)
            self.assertEqual(txin.witness[1], scripts[index])
            digest = unified_witness_v0_sighash(signed, index, scripts[index], spent)
            self.assertTrue(
                verify_ecdsa(pubkey, digest, txin.witness[0][:-1])
            )

    def test_unified_taproot_signature_may_begin_with_der_marker(self) -> None:
        transaction = Transaction(
            2,
            [TxInput(bytes.fromhex("12" * 32), 0)],
            [TxOutput(1, b"\x51")],
        )
        transaction.inputs[0].witness = [
            b"\x30" + b"\x00" * 63 + bytes((BORDINALS_SIGHASH,))
        ]
        self.assertTrue(_funding_signature_types_are_unified(transaction))
        transaction.inputs[0].witness[0] = transaction.inputs[0].witness[0][:-1] + b"\x01"
        self.assertFalse(_funding_signature_types_are_unified(transaction))

    def test_bech32_p2wsh_vectors(self) -> None:
        self.assertEqual(
            p2wsh_address(b"x", "main"),
            "bc1q94c3vs4hy6cygqtz0j5lhtpj7hy9xra3jq7vfkczykr30ys6fzqsmphc8w",
        )
        self.assertEqual(
            p2wsh_address(b"x", "regtest"),
            "bcrt1q94c3vs4hy6cygqtz0j5lhtpj7hy9xra3jq7vfkczykr30ys6fzqspst3gm",
        )


class PolicyPrimitiveTest(unittest.TestCase):
    def test_counterparty_filter_vectors_and_byte_order(self) -> None:
        txid = "e915fa8be0a5d25c4327d056a54bbed7051f6ecf850993994741645012bb0e6b"
        payload = bytes.fromhex(
            "dfa3af7889188ce8034d69efcf5a63a82d6290bbbc54572b93657db6f7d83d"
        )
        self.assertTrue(counterparty_collision(txid, payload))
        self.assertEqual(rc4(bytes.fromhex(txid), payload)[:8], b"CNTRPRTY")
        self.assertFalse(counterparty_collision(txid, payload[:7]))
        self.assertFalse(
            counterparty_collision(txid, bytes((payload[0] ^ 1,)) + payload[1:])
        )
        self.assertFalse(
            counterparty_collision(bytes.fromhex(txid)[::-1].hex(), payload)
        )
        self.assertTrue(
            counterparty_collision("00" * 32, bytes.fromhex("9d56dd13f3650963"))
        )
        self.assertFalse(counterparty_collision(txid, b"BORD\x01\x00\x00\x00"))

    def test_fee_rate_is_decimal_and_bounded_precision(self) -> None:
        self.assertEqual(parse_fee_rate("1.125"), Decimal("1.125"))
        for invalid in ("0", "-1", "NaN", "Infinity", "1.0001"):
            with self.subTest(invalid=invalid):
                with self.assertRaises(MintError):
                    parse_fee_rate(invalid)

    def test_bitcoin_cli_pins_loopback_over_unseen_config(self) -> None:
        local = BitcoinCliRPC("bitcoin-cli", conf="remote-looking.conf")
        self.assertIn("-rpcconnect=127.0.0.1", local._base)
        explicitly_remote = BitcoinCliRPC(
            "bitcoin-cli", conf="remote-looking.conf", allow_remote_rpc=True
        )
        self.assertNotIn("-rpcconnect=127.0.0.1", explicitly_remote._base)
        with self.assertRaisesRegex(MintError, "remote RPC"):
            BitcoinCliRPC("bitcoin-cli", rpcconnect="example.com")

    def test_large_confirmed_reveal_and_unconfirmed_package_boundaries(self) -> None:
        def package_vsize(carriers: int) -> int:
            content = b"x" * (carriers * 1_500)
            manifest = build_manifest(content, "image/svg+xml")
            pubkey = compressed_pubkey(1)
            scripts = [
                build_script(payload, pubkey, carrier_index=index)
                for index, payload in enumerate(encode_payloads(content))
            ]
            funding_input = TxInput(bytes.fromhex("11" * 32), 0)
            funding_input.witness = [b"\x00" * 64 + bytes((BORDINALS_SIGHASH,))]
            funding = Transaction(
                2,
                [funding_input],
                [
                    *[
                        TxOutput(10_000, p2wsh_scriptpubkey(script))
                        for script in scripts
                    ],
                    TxOutput(0, op_return_script(manifest)),
                ],
            )
            reveal = tx_with_placeholder_witnesses(
                [TxInput(bytes.fromhex(funding.txid)[::-1], index) for index in range(carriers)],
                [
                    TxOutput(1, b"\x51\x20" + bytes.fromhex("22" * 32)),
                    TxOutput(0, op_return_script(manifest)),
                ],
                scripts,
            )
            return funding.vsize + reveal.vsize

        # Knots' default package cap is 101,000 vB. The 221-input reveal is
        # individually standard after its parent confirms, but no one-input,
        # no-change parent can make the unconfirmed package fit.
        self.assertLess(package_vsize(177), 101_000)
        self.assertGreater(package_vsize(221), 101_000)


class ConsentAndPlanTest(unittest.TestCase):
    def _consent_document(self) -> dict[str, object]:
        return {
            "schema": "bordinals-consent/1",
            "chain": "regtest",
            "artifact_blake2b256": "ab" * 32,
            "entries": [
                {
                    "address": "bcrt1ptestfixture",
                    "gift_sats": 1000,
                    "label": "opt-in tester",
                    "consent": {
                        "mode": "reference",
                        "reference": "ticket-123",
                        "obtained_at": "2026-09-01T00:00:00Z",
                        "expires_at": "2026-10-01T00:00:00Z",
                    },
                }
            ],
        }

    def test_consent_file_is_artifact_bound_and_unexpired(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "recipients.json"
            path.write_text(json.dumps(self._consent_document()), encoding="utf-8")
            records = load_consent_records(
                path,
                chain="regtest",
                artifact_digest="ab" * 32,
                now=datetime(2026, 9, 3, tzinfo=timezone.utc),
            )
            self.assertEqual(records[0]["gift_sats"], 1000)
            with self.assertRaisesRegex(MintError, "different artifact"):
                load_consent_records(
                    path,
                    chain="regtest",
                    artifact_digest="cd" * 32,
                    now=datetime(2026, 9, 3, tzinfo=timezone.utc),
                )
            with self.assertRaisesRegex(MintError, "expired"):
                load_consent_records(
                    path,
                    chain="regtest",
                    artifact_digest="ab" * 32,
                    now=datetime(2026, 11, 3, tzinfo=timezone.utc),
                )

    def test_unknown_consent_fields_fail_closed(self) -> None:
        document = self._consent_document()
        document["surprise"] = True
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "recipients.json"
            path.write_text(json.dumps(document), encoding="utf-8")
            with self.assertRaisesRegex(MintError, "unknown fields"):
                load_consent_records(
                    path,
                    chain="regtest",
                    artifact_digest="ab" * 32,
                    now=datetime(2026, 9, 3, tzinfo=timezone.utc),
                )

    def test_mode_0600_plan_and_checksum(self) -> None:
        plan = valid_plan()
        verify_plan(plan)
        damaged = dict(plan)
        damaged["state"] = "changed"
        with self.assertRaisesRegex(MintError, "checksum"):
            verify_plan(damaged)
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "plan.json"
            write_new_private_json(path, plan)
            self.assertEqual(path.stat().st_mode & 0o777, 0o600)
            with locked_plan(path) as loaded:
                self.assertEqual(loaded, plan)
            with self.assertRaisesRegex(MintError, "refusing to overwrite"):
                write_new_private_json(path, plan)

    def test_missing_mainnet_ack_causes_zero_rpc_calls(self) -> None:
        plan = valid_plan(chain="main")
        rpc = RecordingRPC()
        with self.assertRaisesRegex(MintError, "mainnet broadcast requires"):
            broadcast_plan_stage(
                rpc,
                plan,
                stage="funding",
                selection="all",
                execute=True,
                acknowledgement=None,
            )
        self.assertEqual(rpc.calls, [])

    def test_full_plan_and_adversarial_field_types_fail_as_mint_errors(self) -> None:
        plan = valid_plan()
        verify_plan(plan)
        mutations = [
            (("schema_version",), True),
            (("chain_snapshot", "chain"), []),
            (("artifact", "blake2b256"), None),
            (("artifact", "mime"), None),
            (("artifact", "length"), True),
            (("entries", 0, "recipient_script_pubkey"), None),
            (("entries", 0, "carrier_pubkey"), None),
            (("entries", 0, "carrier_count"), True),
            (("entries", 0, "refund", "script_pubkey"), None),
            (("entries", 0, "funding", "fee_sats"), None),
            (("entries", 0, "recipient", "consent", "mode"), "bogus"),
            (("policy", "fee_rate_sat_vb"), True),
            (("totals", "recipients"), True),
        ]
        for path, value in mutations:
            with self.subTest(path=path):
                damaged = copy.deepcopy(plan)
                cursor = damaged
                for key in path[:-1]:
                    cursor = cursor[key]
                cursor[path[-1]] = value
                damaged = seal_plan(damaged)
                with self.assertRaises(MintError):
                    verify_plan(damaged)
        for path in (
            ("entries", 0, "funding", "fee_sats"),
            ("entries", 0, "reveal", "fee_sats"),
            ("entries", 0, "refund", "fee_sats"),
            ("entries", 0, "refund", "value_sats"),
        ):
            with self.subTest(deleted=path):
                damaged = copy.deepcopy(plan)
                cursor = damaged
                for key in path[:-1]:
                    cursor = cursor[key]
                del cursor[path[-1]]
                damaged = seal_plan(damaged)
                with self.assertRaises(MintError):
                    verify_plan(damaged)

    def test_mainnet_approval_is_bound_to_exact_checksum(self) -> None:
        plan = valid_plan(chain="main")
        old_checksum = plan["checksum_blake2b256"]
        damaged = copy.deepcopy(plan)
        damaged["entries"][0]["recipient"]["label"] = "changed after review"
        damaged = seal_plan(damaged)
        rpc = RecordingRPC()
        with self.assertRaisesRegex(MintError, "approve-plan-checksum"):
            broadcast_plan_stage(
                rpc,
                damaged,
                stage="funding",
                selection="0",
                execute=True,
                acknowledgement=BROADCAST_ACK,
                approved_plan_checksum=old_checksum,
            )
        self.assertEqual(rpc.calls, [])

    def test_mainnet_rejects_all_before_rpc(self) -> None:
        plan = valid_plan(chain="main")
        rpc = RecordingRPC()
        with self.assertRaisesRegex(MintError, "one explicit"):
            broadcast_plan_stage(
                rpc,
                plan,
                stage="funding",
                selection="all",
                execute=True,
                acknowledgement=BROADCAST_ACK,
                approved_plan_checksum=plan["checksum_blake2b256"],
            )
        self.assertEqual(rpc.calls, [])


class JournalAndCleanupTest(unittest.TestCase):
    def test_journal_corruption_and_plan_binding_fail_closed(self) -> None:
        plan = valid_plan()
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            corrupt_path = root / "corrupt.state.jsonl"
            with create_valid_journal(corrupt_path, plan):
                pass
            lines = corrupt_path.read_text(encoding="utf-8").splitlines()
            changed_record = json.loads(lines[1])
            changed_record["inputs"][0]["vout"] += 1
            lines[1] = json.dumps(changed_record, separators=(",", ":"), sort_keys=True)
            corrupt_path.write_text("\n".join(lines) + "\n", encoding="utf-8")
            with self.assertRaisesRegex(MintError, "record hash"):
                ExecutionJournal.open(corrupt_path)

            binding_path = root / "binding.state.jsonl"
            with create_valid_journal(binding_path, plan):
                pass
            different_plan = copy.deepcopy(plan)
            different_plan["entries"][0]["recipient"]["label"] = "different"
            different_plan = seal_plan(different_plan)
            with ExecutionJournal.open(binding_path) as journal:
                with self.assertRaisesRegex(MintError, "not committed to this exact plan"):
                    journal.validate_for_plan(different_plan)

    def test_funding_attempt_blocks_unlock_after_local_eviction(self) -> None:
        plan = valid_plan()
        rpc = PlanRPC(plan)
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "plan.state.jsonl"
            with create_valid_journal(path, plan) as journal:
                broadcast_plan_stage(
                    rpc,
                    plan,
                    stage="funding",
                    selection="0",
                    execute=True,
                    journal=journal,
                )
            rpc.mempool.clear()
            with ExecutionJournal.open(path) as journal:
                self.assertEqual(journal.unlock_state(0), "blocked")
                with self.assertRaisesRegex(MintError, "cannot be auto-unlocked"):
                    unlock_plan_inputs(
                        rpc,
                        plan,
                        selection="0",
                        journal=journal,
                        execute=True,
                        acknowledgement=UNLOCK_ACK,
                    )
            self.assertTrue(rpc.locks)
            self.assertFalse(
                any(
                    method == "lockunspent" and params[0] is True
                    for method, params in rpc.calls
                )
            )

    def test_spend_choice_permanently_blocks_competitor(self) -> None:
        plan = valid_plan()
        rpc = PlanRPC(plan)
        rpc.add_funding_carriers()
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "plan.state.jsonl"
            with create_valid_journal(path, plan) as journal:
                broadcast_plan_stage(
                    rpc,
                    plan,
                    stage="reveal",
                    selection="0",
                    execute=True,
                    journal=journal,
                )
            rpc.mempool.clear()
            with ExecutionJournal.open(path) as journal:
                with self.assertRaisesRegex(MintError, "permanently selected reveal"):
                    broadcast_plan_stage(
                        rpc,
                        plan,
                        stage="refund",
                        selection="0",
                        execute=True,
                        refund_acknowledgement=REFUND_ACK,
                        journal=journal,
                    )
            self.assertEqual(
                sum(method == "sendrawtransaction" for method, _ in rpc.calls), 1
            )

    def test_irreversible_event_is_synced_before_send(self) -> None:
        plan = valid_plan()

        class OrderingRPC(PlanRPC):
            def __init__(self, journal: ExecutionJournal) -> None:
                super().__init__(plan)
                self.journal = journal
                self.record_at_send: dict[str, object] | None = None

            def call(self, method: str, *params: object) -> object:
                if method == "sendrawtransaction":
                    self.record_at_send = copy.deepcopy(self.journal.records[-1])
                return super().call(method, *params)

        for stage, expected_event in (
            ("funding", "FUNDING_ATTEMPTED"),
            ("reveal", "SPEND_SELECTED"),
        ):
            with self.subTest(stage=stage), tempfile.TemporaryDirectory() as directory:
                with create_valid_journal(
                    Path(directory) / "plan.state.jsonl", plan
                ) as journal:
                    rpc = OrderingRPC(journal)
                    if stage == "reveal":
                        rpc.add_funding_carriers()
                    broadcast_plan_stage(
                        rpc,
                        plan,
                        stage=stage,
                        selection="0",
                        execute=True,
                        journal=journal,
                    )
                    self.assertIsNotNone(rpc.record_at_send)
                    self.assertEqual(rpc.record_at_send["event"], expected_event)
                    self.assertEqual(
                        rpc.record_at_send["txid"], plan["entries"][0][stage]["txid"]
                    )

    def test_cleanup_timeout_after_applied_reconciles(self) -> None:
        plan = valid_plan()
        rpc = UnlockFaultRPC(plan, "timeout-after-applied")
        inputs = plan["entries"][0]["funding"]["locked_wallet_inputs"]
        _cleanup_reserved_after_failure(rpc, inputs, MintError("signing failed"))
        self.assertFalse(rpc.locks)

    def test_cleanup_timeout_before_applied_reports_exact_lock(self) -> None:
        plan = valid_plan()
        rpc = UnlockFaultRPC(plan, "timeout-before-applied")
        inputs = plan["entries"][0]["funding"]["locked_wallet_inputs"]
        primary = MintError("signing failed")
        with self.assertRaises(LockCleanupError) as raised:
            _cleanup_reserved_after_failure(rpc, inputs, primary)
        error = raised.exception
        self.assertIs(error.primary, primary)
        self.assertEqual(error.candidates, inputs)
        self.assertEqual(error.remaining, inputs)
        self.assertIn(f"{inputs[0]['txid']}:{inputs[0]['vout']}", str(error))
        self.assertTrue(rpc.locks)

    def test_unlock_true_but_still_locked_fails_closed(self) -> None:
        plan = valid_plan()
        rpc = UnlockFaultRPC(plan, "true-but-retained")
        inputs = plan["entries"][0]["funding"]["locked_wallet_inputs"]
        with self.assertRaisesRegex(MintError, "reported success but retained"):
            _unlock_exact_wallet_inputs(rpc, inputs)
        self.assertTrue(rpc.locks)

    def test_unlock_intent_resumes_but_terminal_relock_is_refused(self) -> None:
        plan = valid_plan()
        rpc = PlanRPC(plan)
        inputs = plan["entries"][0]["funding"]["locked_wallet_inputs"]
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "plan.state.jsonl"
            with create_valid_journal(path, plan) as journal:
                journal.begin_unlock(0, inputs)
            with ExecutionJournal.open(path) as journal:
                result = unlock_plan_inputs(
                    rpc,
                    plan,
                    selection="0",
                    journal=journal,
                    execute=True,
                    acknowledgement=UNLOCK_ACK,
                )
                self.assertEqual(result["status"], "unlocked")
            rpc.locks.add((inputs[0]["txid"], inputs[0]["vout"]))
            unlock_calls_before = sum(
                method == "lockunspent" for method, _ in rpc.calls
            )
            with ExecutionJournal.open(path) as journal:
                with self.assertRaisesRegex(MintError, "current ownership is unknown"):
                    unlock_plan_inputs(
                        rpc,
                        plan,
                        selection="0",
                        journal=journal,
                        execute=True,
                        acknowledgement=UNLOCK_ACK,
                    )
            self.assertEqual(
                sum(method == "lockunspent" for method, _ in rpc.calls),
                unlock_calls_before,
            )

    def test_unlock_requires_exact_reserved_wallet(self) -> None:
        plan = valid_plan()

        class WrongWalletRPC(PlanRPC):
            def call(self, method: str, *params: object) -> object:
                if method == "getwalletinfo":
                    self.calls.append((method, params))
                    return {
                        "walletname": "other-wallet",
                        "private_keys_enabled": True,
                        "scanning": False,
                    }
                return super().call(method, *params)

        rpc = WrongWalletRPC(plan)
        with tempfile.TemporaryDirectory() as directory:
            with create_valid_journal(
                Path(directory) / "plan.state.jsonl", plan
            ) as journal:
                with self.assertRaisesRegex(MintError, "wallet does not match"):
                    unlock_plan_inputs(
                        rpc, plan, selection="0", journal=journal
                    )
        self.assertTrue(rpc.locks)

    def test_unlock_rejects_same_named_wallet_without_refund_key(self) -> None:
        plan = valid_plan()

        class SameNameWrongKeysRPC(PlanRPC):
            def call(self, method: str, *params: object) -> object:
                if (
                    method == "getaddressinfo"
                    and params[0] == plan["entries"][0]["refund"]["address"]
                ):
                    self.calls.append((method, params))
                    return {
                        "ismine": False,
                        "solvable": False,
                        "iswatchonly": False,
                    }
                return super().call(method, *params)

        rpc = SameNameWrongKeysRPC(plan)
        with tempfile.TemporaryDirectory() as directory:
            with create_valid_journal(
                Path(directory) / "plan.state.jsonl", plan
            ) as journal:
                with self.assertRaisesRegex(MintError, "exact refund address"):
                    unlock_plan_inputs(
                        rpc, plan, selection="0", journal=journal
                    )
                self.assertEqual(journal.unlock_state(0), "available")
        self.assertTrue(rpc.locks)

    def test_journal_refuses_an_append_that_would_cross_size_cap(self) -> None:
        plan = valid_plan()
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "plan.state.jsonl"
            with create_valid_journal(path, plan) as journal:
                size_before = path.stat().st_size
                records_before = copy.deepcopy(journal.records)
                journal._MAX_BYTES = size_before + 1
                with self.assertRaisesRegex(MintError, "exceed its maximum size"):
                    journal.record_funding_irreversible(
                        0, plan["entries"][0]["funding"]["txid"]
                    )
                self.assertEqual(path.stat().st_size, size_before)
                self.assertEqual(journal.records, records_before)


class ExecutionSafetyTest(unittest.TestCase):
    def test_public_execution_flags_require_real_booleans(self) -> None:
        plan = valid_plan()
        rpc = RecordingRPC()
        with self.assertRaisesRegex(MintError, "explicit boolean"):
            broadcast_plan_stage(
                rpc,
                plan,
                stage="funding",
                selection="0",
                execute=1,
            )
        with self.assertRaisesRegex(MintError, "explicit boolean"):
            unlock_plan_inputs(
                rpc, plan, selection="0", journal=None, execute=1  # type: ignore[arg-type]
            )
        self.assertEqual(rpc.calls, [])

    def test_refund_survives_expired_consent_without_wallet_rpcs(self) -> None:
        plan = valid_plan()
        plan["entries"][0]["recipient"]["consent"] = {
            "mode": "reference",
            "reference": "expired-but-refund-must-work",
            "obtained_at": "2020-01-01T00:00:00Z",
            "expires_at": "2021-01-01T00:00:00Z",
        }
        plan = seal_plan(plan)
        rpc = PlanRPC(plan)
        rpc.add_funding_carriers(confirmations=6)
        result = broadcast_plan_stage(
            rpc,
            plan,
            stage="refund",
            selection="0",
            execute=True,
            refund_acknowledgement=REFUND_ACK,
        )
        self.assertEqual(result[0]["status"], "broadcast")
        methods = [method for method, _ in rpc.calls]
        for forbidden in (
            "getnetworkinfo",
            "getdeploymentinfo",
            "getwalletinfo",
            "getaddressinfo",
            "gettransaction",
        ):
            self.assertNotIn(forbidden, methods)

    def test_expired_consent_blocks_delivery_but_not_status(self) -> None:
        plan = valid_plan()
        plan["entries"][0]["recipient"]["consent"] = {
            "mode": "reference",
            "reference": "expired",
            "obtained_at": "2020-01-01T00:00:00Z",
            "expires_at": "2021-01-01T00:00:00Z",
        }
        plan = seal_plan(plan)
        rpc = PlanRPC(plan)
        rpc.add_funding_carriers(confirmations=1)
        with self.assertRaisesRegex(MintError, "consent has expired"):
            broadcast_plan_stage(
                rpc,
                plan,
                stage="reveal",
                selection="0",
                execute=False,
            )
        status = plan_status(rpc, plan)
        self.assertEqual(status["entries"][0]["winner"], "neither-carriers-unspent")
        self.assertNotIn("sendrawtransaction", [method for method, _ in rpc.calls])

    def test_broadcast_defaults_to_read_only_preflight(self) -> None:
        plan = valid_plan()
        rpc = PlanRPC(plan)
        result = broadcast_plan_stage(
            rpc,
            plan,
            stage="funding",
            selection="0",
        )
        self.assertEqual(result[0]["status"], "preflight-ok-not-broadcast")
        self.assertNotIn("sendrawtransaction", [method for method, _ in rpc.calls])

    def test_confirmed_reveal_retry_is_idempotent_without_txindex(self) -> None:
        plan = valid_plan()
        plan["entries"][0]["recipient"]["consent"] = {
            "mode": "reference",
            "reference": "expired-after-confirmation",
            "obtained_at": "2020-01-01T00:00:00Z",
            "expires_at": "2021-01-01T00:00:00Z",
        }
        plan = seal_plan(plan)
        rpc = PlanRPC(plan)
        rpc.add_stage_output("reveal", confirmations=3)
        result = broadcast_plan_stage(
            rpc,
            plan,
            stage="reveal",
            selection="0",
            execute=True,
        )
        self.assertEqual(result[0]["status"], "already-known")
        self.assertEqual(result[0]["confirmations"], 3)
        methods = [method for method, _ in rpc.calls]
        self.assertNotIn("sendrawtransaction", methods)
        self.assertNotIn("getnetworkinfo", methods)
        self.assertNotIn("getdeploymentinfo", methods)

    def test_unlock_is_selective_and_defaults_to_read_only(self) -> None:
        plan = valid_plan()
        rpc = PlanRPC(plan)
        with tempfile.TemporaryDirectory() as directory:
            with create_valid_journal(
                Path(directory) / "plan.json.state.jsonl", plan
            ) as journal:
                dry_run = unlock_plan_inputs(
                    rpc, plan, selection="0", journal=journal
                )
                self.assertEqual(dry_run["status"], "dry-run-not-unlocked")
                self.assertTrue(dry_run["would_unlock"])
                self.assertTrue(rpc.locks)
                result = unlock_plan_inputs(
                    rpc,
                    plan,
                    selection="0",
                    journal=journal,
                    execute=True,
                    acknowledgement=UNLOCK_ACK,
                )
                self.assertEqual(result["status"], "unlocked")
                self.assertTrue(result["unlocked"])
                self.assertFalse(rpc.locks)

    def test_prepare_preview_has_rpc_mutation_guard(self) -> None:
        plan = valid_plan()
        rpc = PlanRPC(plan)
        content = b"<svg xmlns='http://www.w3.org/2000/svg'><text>safe</text></svg>"
        recipient = copy.deepcopy(plan["entries"][0]["recipient"])
        result = preview_preparation(
            rpc,
            content=content,
            artifact_name="safe.svg",
            mime="image/svg+xml",
            recipients=[recipient],
            chain="regtest",
            fee_rate=Decimal("1"),
            max_fee_rate=Decimal("10"),
            max_carriers=177,
            max_reveal_fee_sats=1_000_000,
            max_total_fee_sats=5_000_000,
            max_total_spend_sats=5_000_000,
            consent_ack="I CONFIRM EVERY RECIPIENT OPTED IN",
        )
        self.assertEqual(result["status"], "validated-read-only")
        self.assertEqual(result["mutations"], [])
        methods = {method for method, _ in rpc.calls}
        self.assertFalse(methods & ReadOnlyRPC.MUTATING_METHODS)

    def test_direct_prepare_preview_cannot_bypass_consent_validation(self) -> None:
        plan = valid_plan()
        recipient = copy.deepcopy(plan["entries"][0]["recipient"])
        recipient["consent"]["expires_at"] = "2021-01-01T00:00:00Z"
        rpc = RecordingRPC()
        with self.assertRaisesRegex(MintError, "consent has expired"):
            preview_preparation(
                rpc,
                content=b"<svg/>",
                artifact_name="direct.svg",
                mime="image/svg+xml",
                recipients=[recipient],
                chain="regtest",
                fee_rate=Decimal("1"),
                max_fee_rate=Decimal("10"),
                max_carriers=177,
                max_reveal_fee_sats=1_000_000,
                max_total_fee_sats=5_000_000,
                max_total_spend_sats=5_000_000,
                consent_ack="I CONFIRM EVERY RECIPIENT OPTED IN",
            )
        self.assertEqual(rpc.calls, [])

        recipient = copy.deepcopy(plan["entries"][0]["recipient"])
        recipient["unexpected"] = True
        with self.assertRaisesRegex(MintError, "unknown fields"):
            preview_preparation(
                rpc,
                content=b"<svg/>",
                artifact_name="direct.svg",
                mime="image/svg+xml",
                recipients=[recipient],
                chain="regtest",
                fee_rate=Decimal("1"),
                max_fee_rate=Decimal("10"),
                max_carriers=177,
                max_reveal_fee_sats=1_000_000,
                max_total_fee_sats=5_000_000,
                max_total_spend_sats=5_000_000,
                consent_ack="I CONFIRM EVERY RECIPIENT OPTED IN",
            )
        self.assertEqual(rpc.calls, [])

    def test_cli_broadcast_dispatches_checksum_and_execute(self) -> None:
        plan = valid_plan()
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "plan.json"
            write_new_private_json(path, plan)
            with create_valid_journal(execution_journal_path(path), plan):
                pass
            rpc = PlanRPC(plan)
            output = io.StringIO()
            with (
                patch("bordinals_mint._rpc_from_args", return_value=rpc),
                patch("bordinals_mint.broadcast_plan_stage", return_value=[]) as call,
                redirect_stdout(output),
            ):
                exit_code = main(
                    [
                        "broadcast",
                        str(path),
                        "--stage",
                        "funding",
                        "--entry",
                        "0",
                        "--approve-plan-checksum",
                        plan["checksum_blake2b256"],
                        "--execute",
                    ]
                )
            self.assertEqual(exit_code, 0)
            self.assertTrue(call.call_args.kwargs["execute"])
            self.assertEqual(
                call.call_args.kwargs["approved_plan_checksum"],
                plan["checksum_blake2b256"],
            )


if __name__ == "__main__":
    unittest.main()
