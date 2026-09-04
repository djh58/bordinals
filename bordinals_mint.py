#!/usr/bin/env python3
"""Plan, preflight, and explicitly broadcast BORDINALS mint transactions.

This module deliberately separates preparation from broadcast.  ``prepare``
uses a Bitcoin Knots wallet to fund each independent mint, signs the unusual
P2WSH reveal locally with an ephemeral key, preflights the exact funding and
reveal package, and writes an integrity-checked mode-0600 plan. It never
broadcasts.

The stock Knots signer cannot solve the nonstandard *inner* BORDINALS
witnessScript, even though Knots' current transaction policy accepts the fully
formed spend.  The small signer below therefore implements only the exact
SegWit-v0 ``SIGHASH_ALL|SIGHASH_UNIFIED`` case required by BORDINALS.  A signed
refund to a fresh wallet-owned P2TR address is persisted before the ephemeral
carrier key is discarded.

All command paths are read-only unless ``--execute`` is supplied. Broadcast is
a separate command with an exact acknowledgement. External
recipients must be supplied by the operator with an opt-in reference; this
tool performs no identity-to-address discovery.
"""

from __future__ import annotations

import argparse
from contextlib import contextmanager
from dataclasses import dataclass, field
from decimal import Decimal, InvalidOperation, ROUND_CEILING
import fcntl
import hashlib
import hmac
import json
import os
from pathlib import Path
import re
import secrets
import stat
import struct
import subprocess
import sys
from datetime import datetime, timezone
from typing import Any, Callable, Iterator, Protocol, Sequence

from bordinals import (
    BORDINALS_SIGHASH,
    MAX_DEFAULT_WITNESS_BYTES,
    build_manifest,
    build_script,
    carrier_count,
    decode_committed_witnesses,
    encode_payloads,
    op_return_script,
    p2wsh_scriptpubkey,
    parse_manifest,
    validate_signature_item,
)


FORMAT = "bordinals-mainnet-plan-v2"
SCHEMA_VERSION = 2
JOURNAL_FORMAT = "bordinals-execution-journal-v1"
JOURNAL_SCHEMA_VERSION = 1
JOURNAL_SUFFIX = ".state.jsonl"
MAX_STANDARD_CARRIERS = 221
DEFAULT_MAX_CARRIERS = 177
MAX_RECIPIENTS = 100
MAINNET_GENESIS = (
    "000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f"
)
REGTEST_GENESIS = (
    "0f9188f13cb7b2c71f2a335e3a4fc328bf5beb436012afca590b1a11466e2206"
)
CONSENT_ACK = "I CONFIRM EVERY RECIPIENT OPTED IN"
MAINNET_PREPARE_ACK = "I UNDERSTAND THIS LOCKS REAL MAINNET COINS"
BROADCAST_ACK = "I UNDERSTAND THIS BROADCASTS REAL MAINNET COINS"
REFUND_ACK = "I CHOOSE REFUND INSTEAD OF THE RECIPIENT DELIVERY"
LARGE_ACK = "I ACCEPT A 178-221 CARRIER EXPERIMENT"
UNLOCK_ACK = "I CONFIRM THIS EXACT FUNDING TRANSACTION WAS NEVER SUBMITTED BY ANY MEANS"

SATOSHIS = Decimal(100_000_000)
MAX_MONEY_SATS = 21_000_000 * 100_000_000

SECP256K1_P = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F
SECP256K1_N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
SECP256K1_G = (
    0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798,
    0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8,
)


class MintError(RuntimeError):
    """A safe, user-facing BORDINALS minter failure."""


class KnotsRPCError(MintError):
    """A structured bitcoin-cli JSON-RPC failure."""

    def __init__(self, method: str, detail: str, code: int | None = None) -> None:
        super().__init__(f"Knots RPC {method} failed: {detail}")
        self.method = method
        self.code = code


class LockCleanupError(MintError):
    """Preparation failed and exact wallet-lock recovery was incomplete."""

    def __init__(
        self,
        primary: BaseException,
        candidates: Sequence[dict[str, Any]],
        remaining: Sequence[dict[str, Any]] | None,
        cleanup_error: BaseException | None = None,
    ) -> None:
        self.primary = primary
        self.candidates = list(candidates)
        self.remaining = None if remaining is None else list(remaining)
        self.cleanup_error = cleanup_error
        at_risk = self.candidates if remaining is None else self.remaining
        rendered = ", ".join(
            f"{item['txid']}:{item['vout']}" for item in at_risk
        )
        if remaining is None:
            state = "wallet lock state could not be confirmed"
        else:
            state = f"{len(remaining)} wallet input(s) remain persistently locked"
        detail = f"; cleanup RPC also failed: {cleanup_error}" if cleanup_error else ""
        super().__init__(
            f"preparation failed: {primary}. SAFETY: {state}: {rendered}{detail}. "
            "No transaction was broadcast by prepare. Stop before preparing again; "
            "inspect listlockunspent and release only these exact outpoints after "
            "confirming their saved funding transaction was never broadcast."
        )


class RPC(Protocol):
    def call(self, method: str, *params: Any) -> Any:
        """Call one Bitcoin Knots JSON-RPC method."""


class BitcoinCliRPC:
    """Cookie-authenticated RPC transport through the official bitcoin-cli."""

    def __init__(
        self,
        bitcoin_cli: str,
        *,
        wallet: str | None = None,
        datadir: str | None = None,
        conf: str | None = None,
        rpcconnect: str | None = None,
        rpcport: int | None = None,
        allow_remote_rpc: bool = False,
        timeout: int = 180,
    ) -> None:
        if rpcconnect and not _is_loopback_host(rpcconnect) and not allow_remote_rpc:
            raise MintError(
                "remote RPC is refused by default; use --allow-remote-rpc explicitly"
            )
        self._base = [bitcoin_cli]
        if wallet:
            self._base.append(f"-rpcwallet={wallet}")
        if datadir:
            self._base.append(f"-datadir={datadir}")
        if conf:
            self._base.append(f"-conf={conf}")
        if rpcconnect:
            self._base.append(f"-rpcconnect={rpcconnect}")
        elif not allow_remote_rpc:
            # bitcoin-cli otherwise inherits rpcconnect from bitcoin.conf. Pin
            # the command line to loopback so an unseen config cannot bypass
            # the default local-RPC boundary.
            self._base.append("-rpcconnect=127.0.0.1")
        if rpcport is not None:
            self._base.append(f"-rpcport={rpcport}")
        self._timeout = timeout

    def call(self, method: str, *params: Any) -> Any:
        command = [*self._base, method, *(_encode_cli_arg(item) for item in params)]
        try:
            result = subprocess.run(
                command,
                check=False,
                capture_output=True,
                text=True,
                timeout=self._timeout,
            )
        except (OSError, subprocess.TimeoutExpired) as exc:
            raise MintError(f"bitcoin-cli failed for {method}: {exc}") from exc
        if result.returncode:
            detail = (result.stderr or result.stdout).strip()
            match = re.search(r"error code:\s*(-?\d+)", detail)
            code = int(match.group(1)) if match else None
            raise KnotsRPCError(method, detail, code)
        output = result.stdout.strip()
        if not output:
            return None
        try:
            return json.loads(output, parse_float=Decimal)
        except json.JSONDecodeError:
            return output


class ReadOnlyRPC:
    """Defense-in-depth guard for default dry-run command paths."""

    MUTATING_METHODS = {
        "getnewaddress",
        "getrawchangeaddress",
        "walletcreatefundedpsbt",
        "walletprocesspsbt",
        "lockunspent",
        "sendrawtransaction",
    }

    def __init__(self, rpc: RPC) -> None:
        self._rpc = rpc

    def call(self, method: str, *params: Any) -> Any:
        if method in self.MUTATING_METHODS:
            raise MintError(f"read-only mode refuses mutating RPC {method}")
        return self._rpc.call(method, *params)


def _is_loopback_host(host: str) -> bool:
    normalized = host.strip().strip("[]").lower()
    return normalized in {"localhost", "127.0.0.1", "::1"}


def _encode_cli_arg(value: Any) -> str:
    if isinstance(value, str):
        return value
    if isinstance(value, Decimal):
        return format(value, "f")
    return json.dumps(value, separators=(",", ":"), ensure_ascii=True)


def sha256(data: bytes) -> bytes:
    return hashlib.sha256(data).digest()


def hash256(data: bytes) -> bytes:
    return sha256(sha256(data))


def tagged_hash(tag: str, payload: bytes) -> bytes:
    tag_hash = sha256(tag.encode("ascii"))
    return sha256(tag_hash + tag_hash + payload)


def compact_size(value: int) -> bytes:
    if value < 0:
        raise MintError("CompactSize cannot encode a negative value")
    if value < 253:
        return bytes((value,))
    if value <= 0xFFFF:
        return b"\xfd" + struct.pack("<H", value)
    if value <= 0xFFFFFFFF:
        return b"\xfe" + struct.pack("<I", value)
    if value <= 0xFFFFFFFFFFFFFFFF:
        return b"\xff" + struct.pack("<Q", value)
    raise MintError("CompactSize value is too large")


def varbytes(value: bytes) -> bytes:
    return compact_size(len(value)) + value


@dataclass
class TxInput:
    prev_txid_le: bytes
    prev_vout: int
    script_sig: bytes = b""
    sequence: int = 0xFFFFFFFD
    witness: list[bytes] = field(default_factory=list)

    def outpoint(self) -> bytes:
        if len(self.prev_txid_le) != 32:
            raise MintError("transaction input txid must be 32 bytes")
        return self.prev_txid_le + struct.pack("<I", self.prev_vout)

    @property
    def prev_txid(self) -> str:
        return self.prev_txid_le[::-1].hex()

    def serialize(self) -> bytes:
        return (
            self.outpoint()
            + varbytes(self.script_sig)
            + struct.pack("<I", self.sequence)
        )


@dataclass(frozen=True)
class TxOutput:
    value_sats: int
    script_pubkey: bytes

    def serialize(self) -> bytes:
        if not 0 <= self.value_sats <= MAX_MONEY_SATS:
            raise MintError("transaction output value is outside the money range")
        return struct.pack("<q", self.value_sats) + varbytes(self.script_pubkey)


@dataclass
class Transaction:
    version: int
    inputs: list[TxInput]
    outputs: list[TxOutput]
    locktime: int = 0

    def serialize(self, *, include_witness: bool = True) -> bytes:
        has_witness = include_witness and any(item.witness for item in self.inputs)
        result = bytearray(struct.pack("<i", self.version))
        if has_witness:
            result.extend(b"\x00\x01")
        result.extend(compact_size(len(self.inputs)))
        for txin in self.inputs:
            result.extend(txin.serialize())
        result.extend(compact_size(len(self.outputs)))
        for txout in self.outputs:
            result.extend(txout.serialize())
        if has_witness:
            for txin in self.inputs:
                result.extend(compact_size(len(txin.witness)))
                for item in txin.witness:
                    result.extend(varbytes(item))
        result.extend(struct.pack("<I", self.locktime))
        return bytes(result)

    @property
    def txid(self) -> str:
        return hash256(self.serialize(include_witness=False))[::-1].hex()

    @property
    def wtxid(self) -> str:
        return hash256(self.serialize(include_witness=True))[::-1].hex()

    @property
    def weight(self) -> int:
        stripped = len(self.serialize(include_witness=False))
        total = len(self.serialize(include_witness=True))
        return stripped * 4 + total - stripped

    @property
    def vsize(self) -> int:
        return (self.weight + 3) // 4


class _Reader:
    def __init__(self, data: bytes) -> None:
        self.data = data
        self.offset = 0

    def take(self, count: int) -> bytes:
        if count < 0 or self.offset + count > len(self.data):
            raise MintError("raw transaction is truncated")
        value = self.data[self.offset:self.offset + count]
        self.offset += count
        return value

    def u8(self) -> int:
        return self.take(1)[0]

    def compact_size(self) -> int:
        prefix = self.u8()
        if prefix < 253:
            return prefix
        if prefix == 253:
            value = struct.unpack("<H", self.take(2))[0]
            if value < 253:
                raise MintError("non-canonical CompactSize")
            return value
        if prefix == 254:
            value = struct.unpack("<I", self.take(4))[0]
            if value <= 0xFFFF:
                raise MintError("non-canonical CompactSize")
            return value
        value = struct.unpack("<Q", self.take(8))[0]
        if value <= 0xFFFFFFFF:
            raise MintError("non-canonical CompactSize")
        return value

    def varbytes(self) -> bytes:
        return self.take(self.compact_size())


def parse_transaction(raw_hex: str) -> Transaction:
    try:
        raw = bytes.fromhex(raw_hex)
    except ValueError as exc:
        raise MintError("raw transaction is not hexadecimal") from exc
    reader = _Reader(raw)
    version = struct.unpack("<i", reader.take(4))[0]
    marker_offset = reader.offset
    input_count = reader.compact_size()
    has_witness = False
    if input_count == 0:
        flag = reader.u8()
        if flag != 1:
            raise MintError("raw transaction witness flag must be exactly 1")
        has_witness = True
        input_count = reader.compact_size()
    elif raw[marker_offset] == 0:
        raise MintError("raw transaction has an invalid marker")
    if input_count == 0:
        raise MintError("raw transaction has no inputs")
    inputs: list[TxInput] = []
    for _ in range(input_count):
        inputs.append(
            TxInput(
                prev_txid_le=reader.take(32),
                prev_vout=struct.unpack("<I", reader.take(4))[0],
                script_sig=reader.varbytes(),
                sequence=struct.unpack("<I", reader.take(4))[0],
            )
        )
    output_count = reader.compact_size()
    outputs: list[TxOutput] = []
    for _ in range(output_count):
        value_sats = struct.unpack("<q", reader.take(8))[0]
        outputs.append(TxOutput(value_sats, reader.varbytes()))
    if has_witness:
        for txin in inputs:
            txin.witness = [reader.varbytes() for _ in range(reader.compact_size())]
        if not any(txin.witness for txin in inputs):
            raise MintError("raw transaction has a superfluous witness record")
    locktime = struct.unpack("<I", reader.take(4))[0]
    if reader.offset != len(raw):
        raise MintError("raw transaction has trailing bytes")
    return Transaction(version, inputs, outputs, locktime)


def unified_witness_v0_sighash(
    transaction: Transaction,
    input_index: int,
    script_code: bytes,
    spent_outputs: Sequence[TxOutput],
    hash_type: int = BORDINALS_SIGHASH,
) -> bytes:
    """Compute Knots' v29.4.1 unified SegWit-v0 signature hash."""
    if not 0 <= input_index < len(transaction.inputs):
        raise MintError("signature input index is out of range")
    if len(spent_outputs) != len(transaction.inputs):
        raise MintError("unified sighash requires every spent output")
    if hash_type != BORDINALS_SIGHASH:
        raise MintError("BORDINALS only signs ALL|UNIFIED (0x21)")

    message = bytearray((0, hash_type))
    message.extend(struct.pack("<i", transaction.version))
    message.extend(struct.pack("<I", transaction.locktime))
    message.append(0)  # Reserved fifth locktime byte in Knots' format.
    message.extend(sha256(b"".join(item.outpoint() for item in transaction.inputs)))
    message.extend(
        sha256(b"".join(struct.pack("<q", item.value_sats) for item in spent_outputs))
    )
    message.extend(sha256(b"".join(varbytes(item.script_pubkey) for item in spent_outputs)))
    message.extend(
        sha256(b"".join(struct.pack("<I", item.sequence) for item in transaction.inputs))
    )
    message.extend(sha256(b"".join(item.serialize() for item in transaction.outputs)))
    message.append(1)  # UNIFIED_SCRIPT_TYPE_WITNESS_V0
    message.extend(struct.pack("<I", input_index))
    message.extend(varbytes(script_code))
    return tagged_hash("UnifiedSighash", bytes(message))


Point = tuple[int, int] | None


def _point_add(first: Point, second: Point) -> Point:
    if first is None:
        return second
    if second is None:
        return first
    x1, y1 = first
    x2, y2 = second
    if x1 == x2 and (y1 + y2) % SECP256K1_P == 0:
        return None
    if first == second:
        slope = (3 * x1 * x1) * pow(2 * y1, -1, SECP256K1_P)
    else:
        slope = (y2 - y1) * pow(x2 - x1, -1, SECP256K1_P)
    slope %= SECP256K1_P
    x3 = (slope * slope - x1 - x2) % SECP256K1_P
    y3 = (slope * (x1 - x3) - y1) % SECP256K1_P
    return x3, y3


def _point_mul(scalar: int, point: Point = SECP256K1_G) -> Point:
    if scalar % SECP256K1_N == 0 or point is None:
        return None
    result: Point = None
    addend = point
    while scalar:
        if scalar & 1:
            result = _point_add(result, addend)
        addend = _point_add(addend, addend)
        scalar >>= 1
    return result


def compressed_pubkey(secret: int) -> bytes:
    if not 1 <= secret < SECP256K1_N:
        raise MintError("carrier private key is outside the curve order")
    point = _point_mul(secret)
    if point is None:
        raise AssertionError("valid secret produced the point at infinity")
    x, y = point
    return bytes((2 | (y & 1),)) + x.to_bytes(32, "big")


def _rfc6979_nonces(secret: int, digest: bytes) -> Iterator[int]:
    if len(digest) != 32:
        raise MintError("ECDSA digest must contain 32 bytes")
    key = secret.to_bytes(32, "big")
    reduced = (int.from_bytes(digest, "big") % SECP256K1_N).to_bytes(32, "big")
    k = b"\x00" * 32
    v = b"\x01" * 32
    k = hmac.new(k, v + b"\x00" + key + reduced, hashlib.sha256).digest()
    v = hmac.new(k, v, hashlib.sha256).digest()
    k = hmac.new(k, v + b"\x01" + key + reduced, hashlib.sha256).digest()
    v = hmac.new(k, v, hashlib.sha256).digest()
    while True:
        v = hmac.new(k, v, hashlib.sha256).digest()
        candidate = int.from_bytes(v, "big")
        if 1 <= candidate < SECP256K1_N:
            yield candidate
        k = hmac.new(k, v + b"\x00", hashlib.sha256).digest()
        v = hmac.new(k, v, hashlib.sha256).digest()


def _der_integer(value: int) -> bytes:
    encoded = value.to_bytes((value.bit_length() + 7) // 8 or 1, "big")
    if encoded[0] & 0x80:
        encoded = b"\x00" + encoded
    return b"\x02" + bytes((len(encoded),)) + encoded


def sign_ecdsa_low_s(secret: int, digest: bytes) -> bytes:
    """Return deterministic strict-DER, low-S secp256k1 ECDSA."""
    if not 1 <= secret < SECP256K1_N:
        raise MintError("carrier private key is outside the curve order")
    z = int.from_bytes(digest, "big")
    for nonce in _rfc6979_nonces(secret, digest):
        nonce_point = _point_mul(nonce)
        if nonce_point is None:
            continue
        r = nonce_point[0] % SECP256K1_N
        if r == 0:
            continue
        s = (pow(nonce, -1, SECP256K1_N) * (z + r * secret)) % SECP256K1_N
        if s == 0:
            continue
        if s > SECP256K1_N // 2:
            s = SECP256K1_N - s
        body = _der_integer(r) + _der_integer(s)
        return b"\x30" + bytes((len(body),)) + body
    raise AssertionError("RFC6979 did not produce a usable nonce")


def verify_ecdsa(pubkey: bytes, digest: bytes, signature_der: bytes) -> bool:
    """Small verification helper used by plan invariants and unit tests."""
    try:
        r, s = _parse_der_signature(signature_der)
        point = _decompress_pubkey(pubkey)
    except MintError:
        return False
    if not (1 <= r < SECP256K1_N and 1 <= s < SECP256K1_N):
        return False
    z = int.from_bytes(digest, "big")
    inverse = pow(s, -1, SECP256K1_N)
    candidate = _point_add(
        _point_mul((z * inverse) % SECP256K1_N),
        _point_mul((r * inverse) % SECP256K1_N, point),
    )
    return candidate is not None and candidate[0] % SECP256K1_N == r


def _parse_der_signature(signature: bytes) -> tuple[int, int]:
    if len(signature) < 8 or signature[0] != 0x30 or signature[1] != len(signature) - 2:
        raise MintError("invalid DER ECDSA signature")
    if signature[2] != 2:
        raise MintError("invalid DER R integer")
    r_len = signature[3]
    r_end = 4 + r_len
    if r_len == 0 or r_end + 2 > len(signature) or signature[r_end] != 2:
        raise MintError("invalid DER R length")
    s_len = signature[r_end + 1]
    s_start = r_end + 2
    if s_len == 0 or s_start + s_len != len(signature):
        raise MintError("invalid DER S length")
    r_bytes = signature[4:r_end]
    s_bytes = signature[s_start:]
    if r_bytes[0] & 0x80 or s_bytes[0] & 0x80:
        raise MintError("negative DER integer")
    if len(r_bytes) > 1 and r_bytes[0] == 0 and not r_bytes[1] & 0x80:
        raise MintError("non-minimal DER R integer")
    if len(s_bytes) > 1 and s_bytes[0] == 0 and not s_bytes[1] & 0x80:
        raise MintError("non-minimal DER S integer")
    return int.from_bytes(r_bytes, "big"), int.from_bytes(s_bytes, "big")


def _decompress_pubkey(pubkey: bytes) -> tuple[int, int]:
    if len(pubkey) != 33 or pubkey[0] not in (2, 3):
        raise MintError("invalid compressed public key")
    x = int.from_bytes(pubkey[1:], "big")
    if x >= SECP256K1_P:
        raise MintError("compressed public key x-coordinate is out of range")
    y_squared = (pow(x, 3, SECP256K1_P) + 7) % SECP256K1_P
    y = pow(y_squared, (SECP256K1_P + 1) // 4, SECP256K1_P)
    if pow(y, 2, SECP256K1_P) != y_squared:
        raise MintError("compressed public key is not on secp256k1")
    if (y & 1) != (pubkey[0] & 1):
        y = SECP256K1_P - y
    return x, y


def rc4(key: bytes, data: bytes) -> bytes:
    """The exact RC4 transform used by Knots' Counterparty filter."""
    if len(key) != 32:
        raise MintError("Counterparty key must be a 32-byte transaction id")
    state = list(range(256))
    j = 0
    for i in range(256):
        j = (j + state[i] + key[i % len(key)]) & 0xFF
        state[i], state[j] = state[j], state[i]
    result = bytearray()
    i = j = 0
    for byte in data:
        i = (i + 1) & 0xFF
        j = (j + state[i]) & 0xFF
        state[i], state[j] = state[j], state[i]
        result.append(byte ^ state[(state[i] + state[j]) & 0xFF])
    return bytes(result)


def counterparty_collision(first_prevout_txid: str, payload: bytes) -> bool:
    if len(payload) < 8:
        return False
    try:
        key = bytes.fromhex(first_prevout_txid)
    except ValueError as exc:
        raise MintError("Counterparty txid key is not hexadecimal") from exc
    if len(key) != 32:
        raise MintError("Counterparty txid key must be 64 hexadecimal characters")
    return rc4(key, payload[:8]) == b"CNTRPRTY"


def parse_fee_rate(value: str) -> Decimal:
    if not isinstance(value, str):
        raise MintError("fee rate must be a decimal string in sat/vB")
    try:
        rate = Decimal(value)
    except (InvalidOperation, TypeError, ValueError) as exc:
        raise MintError("fee rate must be a decimal number in sat/vB") from exc
    if not rate.is_finite() or rate <= 0:
        raise MintError("fee rate must be finite and greater than zero")
    if rate.as_tuple().exponent < -3:
        raise MintError("fee rate may have at most three decimal places")
    return rate


def sats_to_btc(sats: int) -> float:
    if not 0 <= sats <= MAX_MONEY_SATS:
        raise MintError("satoshi amount is outside the money range")
    return float(Decimal(sats) / SATOSHIS)


def btc_to_sats(value: Any) -> int:
    try:
        amount = Decimal(str(value)) * SATOSHIS
    except InvalidOperation as exc:
        raise MintError("RPC returned an invalid Bitcoin amount") from exc
    integral = amount.to_integral_value()
    if amount != integral:
        raise MintError("RPC returned a sub-satoshi amount")
    sats = int(integral)
    if not -MAX_MONEY_SATS <= sats <= MAX_MONEY_SATS:
        raise MintError("RPC returned an amount outside the money range")
    return sats


def fee_for_vsize(rate: Decimal, vsize: int) -> int:
    return int((rate * vsize).to_integral_value(rounding=ROUND_CEILING))


def fee_rate_limit_btc_kvb(rate: Decimal) -> Decimal:
    return rate * Decimal(1000) / SATOSHIS


def tx_with_placeholder_witnesses(
    inputs: Sequence[TxInput], outputs: Sequence[TxOutput], scripts: Sequence[bytes]
) -> Transaction:
    if len(inputs) != len(scripts):
        raise MintError("placeholder script count does not match inputs")
    cloned = [
        TxInput(item.prev_txid_le, item.prev_vout, item.script_sig, item.sequence)
        for item in inputs
    ]
    for txin, script in zip(cloned, scripts, strict=True):
        txin.witness = [b"\x00" * 73, script]
    return Transaction(2, cloned, list(outputs), 0)


def sign_carrier_transaction(
    transaction: Transaction,
    spent_outputs: Sequence[TxOutput],
    scripts: Sequence[bytes],
    secret: int,
) -> Transaction:
    if len(transaction.inputs) != len(spent_outputs) or len(scripts) != len(spent_outputs):
        raise MintError("carrier signing data does not match transaction inputs")
    pubkey = compressed_pubkey(secret)
    transaction.inputs = [
        TxInput(item.prev_txid_le, item.prev_vout, item.script_sig, item.sequence)
        for item in transaction.inputs
    ]
    for index, (txin, script) in enumerate(zip(transaction.inputs, scripts, strict=True)):
        digest = unified_witness_v0_sighash(
            transaction, index, script, spent_outputs, BORDINALS_SIGHASH
        )
        signature = sign_ecdsa_low_s(secret, digest) + bytes((BORDINALS_SIGHASH,))
        validate_signature_item(signature)
        if not verify_ecdsa(pubkey, digest, signature[:-1]):
            raise AssertionError("locally generated carrier signature did not verify")
        txin.witness = [signature, script]
    return transaction


def _canonical_json(data: Any) -> bytes:
    return json.dumps(
        data, sort_keys=True, separators=(",", ":"), ensure_ascii=True
    ).encode("utf-8")


def plan_checksum(plan_without_checksum: dict[str, Any]) -> str:
    return hashlib.blake2b(_canonical_json(plan_without_checksum), digest_size=32).hexdigest()


def seal_plan(plan: dict[str, Any]) -> dict[str, Any]:
    sealed = dict(plan)
    sealed.pop("checksum_blake2b256", None)
    sealed["checksum_blake2b256"] = plan_checksum(sealed)
    return sealed


def verify_plan(plan: dict[str, Any]) -> None:
    if not isinstance(plan, dict):
        raise MintError("BORDINALS plan must be a JSON object")
    schema_version = plan.get("schema_version")
    if (
        plan.get("format") != FORMAT
        or isinstance(schema_version, bool)
        or schema_version != SCHEMA_VERSION
    ):
        raise MintError("unsupported or malformed BORDINALS plan")
    _require_exact_keys(
        plan,
        required={
            "format",
            "schema_version",
            "plan_id",
            "created_at",
            "state",
            "reservation",
            "chain_snapshot",
            "artifact",
            "policy",
            "totals",
            "entries",
            "checksum_blake2b256",
        },
        optional=set(),
        description="BORDINALS plan",
    )
    expected = plan.get("checksum_blake2b256")
    unsigned = dict(plan)
    unsigned.pop("checksum_blake2b256", None)
    actual = plan_checksum(unsigned)
    if (
        not isinstance(expected, str)
        or len(expected) != 64
        or expected != expected.lower()
        or any(char not in "0123456789abcdef" for char in expected)
        or not hmac.compare_digest(expected, actual)
    ):
        raise MintError("BORDINALS plan checksum does not match")
    entries = plan.get("entries", [])
    if not isinstance(entries, list):
        raise MintError("BORDINALS plan entries must be a list")
    if not entries:
        raise MintError("BORDINALS plan must contain at least one entry")

    if plan.get("state") != "PREPARED_NOT_BROADCAST":
        raise MintError("BORDINALS plan has an unexpected state")
    _decode_hex_field(plan.get("plan_id"), "BORDINALS plan id", length=16)
    _parse_utc_timestamp(plan.get("created_at"), "plan creation time")
    reservation = _require_dict(plan.get("reservation"), "plan reservation")
    _require_exact_keys(
        reservation,
        required={"id", "wallet_name", "journal_format"},
        optional=set(),
        description="plan reservation",
    )
    _decode_hex_field(reservation.get("id"), "plan reservation id", length=16)
    if not isinstance(reservation.get("wallet_name"), str):
        raise MintError("plan reservation wallet name is malformed")
    if reservation.get("journal_format") != JOURNAL_FORMAT:
        raise MintError("plan reservation journal format is unsupported")
    snapshot = _require_dict(plan.get("chain_snapshot"), "plan chain snapshot")
    chain = snapshot.get("chain")
    if not isinstance(chain, str) or chain not in {"main", "regtest"}:
        raise MintError("plan chain is unsupported")
    expected_genesis = MAINNET_GENESIS if chain == "main" else REGTEST_GENESIS
    if snapshot.get("genesis") != expected_genesis:
        raise MintError("plan chain snapshot has an unexpected genesis block")
    artifact = _require_dict(plan.get("artifact"), "plan artifact")
    policy = _require_dict(plan.get("policy"), "plan policy")
    totals = _require_dict(plan.get("totals"), "plan totals")
    _require_exact_keys(
        artifact,
        required={"name", "mime", "length", "blake2b256", "carrier_count"},
        optional=set(),
        description="plan artifact",
    )
    _require_exact_keys(
        policy,
        required={
            "consent",
            "fee_rate_sat_vb",
            "max_fee_rate_sat_vb",
            "max_carriers",
            "max_funding_fee_sats_each",
            "max_reveal_fee_sats_each",
            "max_total_fee_sats",
            "max_total_spend_sats",
            "maxfeerate_rpc_btc_kvb",
            "requires_funding_confirmations",
        },
        optional=set(),
        description="plan policy",
    )
    _require_exact_keys(
        totals,
        required={
            "recipients",
            "gift_sats",
            "normal_path_fee_sats",
            "normal_path_spend_sats",
            "temporarily_locked_carrier_sats",
        },
        optional=set(),
        description="plan totals",
    )
    if not isinstance(artifact.get("name"), str) or not artifact["name"]:
        raise MintError("plan artifact name is malformed")
    artifact_length = artifact.get("length")
    artifact_count = artifact.get("carrier_count")
    artifact_digest = artifact.get("blake2b256")
    artifact_mime = artifact.get("mime")
    if (
        isinstance(artifact_length, bool)
        or not isinstance(artifact_length, int)
        or artifact_length <= 0
        or isinstance(artifact_count, bool)
        or not isinstance(artifact_count, int)
        or artifact_count != carrier_count(artifact_length)
    ):
        raise MintError("plan artifact length or carrier count is malformed")
    digest_bytes = _decode_hex_field(
        artifact_digest, "plan artifact digest", length=32
    )
    if not isinstance(artifact_mime, str) or not artifact_mime:
        raise MintError("plan artifact MIME type is malformed")
    cap_names = (
        "max_funding_fee_sats_each",
        "max_reveal_fee_sats_each",
        "max_total_fee_sats",
        "max_total_spend_sats",
    )
    for name in cap_names:
        value = policy.get(name)
        if isinstance(value, bool) or not isinstance(value, int) or value <= 0:
            raise MintError(f"plan policy {name} is malformed")
    fee_rate = parse_fee_rate(policy.get("fee_rate_sat_vb"))
    max_fee_rate = parse_fee_rate(policy.get("max_fee_rate_sat_vb"))
    if fee_rate > max_fee_rate:
        raise MintError("saved fee rate exceeds the plan fee-rate cap")
    if policy.get("consent") != "recorded-not-cryptographically-verified":
        raise MintError("plan consent policy is malformed")
    required_confirmations = policy.get("requires_funding_confirmations")
    if isinstance(required_confirmations, bool) or required_confirmations != 1:
        raise MintError("plan confirmation policy is malformed")
    maxfeerate_rpc = policy.get("maxfeerate_rpc_btc_kvb")
    if not isinstance(maxfeerate_rpc, str):
        raise MintError("plan RPC fee ceiling is malformed")
    try:
        recorded_maxfeerate = Decimal(maxfeerate_rpc)
    except InvalidOperation as exc:
        raise MintError("plan RPC fee ceiling is malformed") from exc
    if recorded_maxfeerate != fee_rate_limit_btc_kvb(max_fee_rate):
        raise MintError("plan RPC fee ceiling differs from its sat/vB cap")
    max_carriers = policy.get("max_carriers")
    if (
        isinstance(max_carriers, bool)
        or not isinstance(max_carriers, int)
        or not 1 <= max_carriers <= MAX_STANDARD_CARRIERS
        or artifact_count > max_carriers
    ):
        raise MintError("plan carrier cap is malformed or exceeded")
    if not 1 <= len(entries) <= MAX_RECIPIENTS:
        raise MintError("plan recipient count is outside the supported range")
    for name in (
        "recipients",
        "gift_sats",
        "normal_path_fee_sats",
        "normal_path_spend_sats",
        "temporarily_locked_carrier_sats",
    ):
        value = totals.get(name)
        if isinstance(value, bool) or not isinstance(value, int) or value < 0:
            raise MintError(f"plan total {name} is malformed")

    total_gifts = 0
    total_fees = 0
    total_carrier_sats = 0
    seen_addresses: set[str] = set()
    seen_wallet_inputs: set[tuple[str, int]] = set()
    for index, raw_entry in enumerate(entries):
        entry = _require_dict(raw_entry, f"plan entry {index}")
        _require_exact_keys(
            entry,
            required={
                "index",
                "recipient",
                "recipient_script_pubkey",
                "carrier_pubkey",
                "carrier_count",
                "carrier_vouts",
                "carrier_values_sats",
                "manifest_hex",
                "funding",
                "reveal",
                "refund",
            },
            optional=set(),
            description=f"plan entry {index}",
        )
        entry_index = entry.get("index")
        entry_count = entry.get("carrier_count")
        if (
            isinstance(entry_index, bool)
            or not isinstance(entry_index, int)
            or entry_index != index
            or isinstance(entry_count, bool)
            or not isinstance(entry_count, int)
            or entry_count != artifact_count
        ):
            raise MintError("plan entry index or carrier count changed")
        carrier_vouts = entry.get("carrier_vouts")
        carrier_values = entry.get("carrier_values_sats")
        if (
            not isinstance(carrier_vouts, list)
            or len(carrier_vouts) != artifact_count
            or any(
                isinstance(value, bool) or not isinstance(value, int) or value < 0
                for value in carrier_vouts
            )
            or len(set(carrier_vouts)) != artifact_count
        ):
            raise MintError("saved carrier vouts are malformed")
        if (
            not isinstance(carrier_values, list)
            or len(carrier_values) != artifact_count
            or any(
                isinstance(value, bool) or not isinstance(value, int) or value <= 0
                for value in carrier_values
            )
        ):
            raise MintError("saved carrier values are malformed")
        recipient = _require_dict(entry.get("recipient"), "saved recipient")
        _require_exact_keys(
            recipient,
            required={"address", "gift_sats", "label", "consent"},
            optional=set(),
            description="saved recipient",
        )
        address = recipient.get("address")
        if not isinstance(address, str) or address in seen_addresses:
            raise MintError("plan recipient address is malformed or duplicated")
        seen_addresses.add(address)
        gift_sats = recipient.get("gift_sats")
        if isinstance(gift_sats, bool) or not isinstance(gift_sats, int) or gift_sats <= 0:
            raise MintError("saved gift is malformed")
        if not isinstance(recipient.get("label"), str) or len(recipient["label"]) > 120:
            raise MintError("saved recipient label is malformed")
        consent = _require_dict(recipient.get("consent"), "saved consent")
        mode = consent.get("mode")
        if mode == "self":
            _require_exact_keys(
                consent, required={"mode"}, optional=set(), description="saved consent"
            )
        elif mode == "reference":
            _require_exact_keys(
                consent,
                required={"mode", "reference", "obtained_at", "expires_at"},
                optional=set(),
                description="saved consent",
            )
            reference = consent.get("reference")
            if not isinstance(reference, str) or not reference or len(reference) > 500:
                raise MintError("saved consent reference is malformed")
            obtained = _parse_utc_timestamp(
                consent.get("obtained_at"), "saved consent obtained_at"
            )
            expires = _parse_utc_timestamp(
                consent.get("expires_at"), "saved consent expires_at"
            )
            if expires <= obtained:
                raise MintError("saved consent expiry precedes consent")
        else:
            raise MintError("saved consent mode is malformed")
        for stage in ("funding", "reveal", "refund"):
            record = _require_dict(entry.get(stage), f"saved {stage}")
            required_stage_fields = {
                "hex",
                "txid",
                "wtxid",
                "fee_sats",
                "weight",
                "vsize",
            }
            if stage == "funding":
                required_stage_fields |= {"locked_wallet_inputs", "change"}
            elif stage == "reveal":
                required_stage_fields |= {"pointer_vout", "preflight"}
            else:
                required_stage_fields |= {
                    "address",
                    "script_pubkey",
                    "value_sats",
                    "preflight",
                }
            _require_exact_keys(
                record,
                required=required_stage_fields,
                optional=set(),
                description=f"saved {stage}",
            )
            raw_hex = record.get("hex")
            if not isinstance(raw_hex, str):
                raise MintError(f"saved {stage} transaction bytes are malformed")
            tx = parse_transaction(raw_hex)
            if tx.txid != record.get("txid") or tx.wtxid != record.get("wtxid"):
                raise MintError(f"saved {stage} transaction id does not match its bytes")
            for field in ("fee_sats", "weight", "vsize"):
                value = record.get(field)
                if isinstance(value, bool) or not isinstance(value, int) or value < 0:
                    raise MintError(f"saved {stage} {field} is malformed")
            if stage != "funding" and not isinstance(record.get("preflight"), list):
                raise MintError(f"saved {stage} preflight record is malformed")
            if stage == "reveal":
                pointer_vout = record.get("pointer_vout")
                if isinstance(pointer_vout, bool) or pointer_vout != 0:
                    raise MintError("saved reveal pointer vout is malformed")
            if stage == "refund":
                refund_value = record.get("value_sats")
                if (
                    isinstance(refund_value, bool)
                    or not isinstance(refund_value, int)
                    or refund_value <= 0
                ):
                    raise MintError("saved refund value is malformed")
                if not isinstance(record.get("address"), str) or not record["address"]:
                    raise MintError("saved refund address is malformed")
        try:
            manifest = parse_manifest(
                _decode_hex_field(entry.get("manifest_hex"), "saved manifest")
            )
        except ValueError as exc:
            raise MintError(f"saved manifest is malformed: {exc}") from exc
        if (
            manifest.first_input != 0
            or manifest.pointer_vout != entry["reveal"].get("pointer_vout")
            or manifest.input_count != artifact_count
            or manifest.content_length != artifact_length
            or manifest.content_blake2b256 != digest_bytes
            or manifest.mime != artifact_mime
        ):
            raise MintError("saved manifest differs from the plan artifact")
        _assert_saved_entry_invariants(entry)
        for wallet_input in entry["funding"]["locked_wallet_inputs"]:
            key = (wallet_input["txid"], wallet_input["vout"])
            if key in seen_wallet_inputs:
                raise MintError("a funding wallet input is reused across plan entries")
            seen_wallet_inputs.add(key)
        funding_fee = entry["funding"].get("fee_sats")
        reveal_fee = entry["reveal"].get("fee_sats")
        for value, description in (
            (funding_fee, "funding fee"),
            (reveal_fee, "reveal fee"),
            (gift_sats, "gift"),
        ):
            if isinstance(value, bool) or not isinstance(value, int) or value < 0:
                raise MintError(f"saved {description} is malformed")
        if funding_fee > policy.get("max_funding_fee_sats_each", -1):
            raise MintError("saved funding fee exceeds the plan cap")
        if reveal_fee > policy.get("max_reveal_fee_sats_each", -1):
            raise MintError("saved reveal fee exceeds the plan cap")
        total_gifts += gift_sats
        total_fees += funding_fee + reveal_fee
        total_carrier_sats += sum(carrier_values)
    computed_totals = {
        "recipients": len(entries),
        "gift_sats": total_gifts,
        "normal_path_fee_sats": total_fees,
        "normal_path_spend_sats": total_gifts + total_fees,
        "temporarily_locked_carrier_sats": total_carrier_sats,
    }
    if totals != computed_totals:
        raise MintError("saved aggregate totals differ from the exact transactions")
    if total_fees > policy.get("max_total_fee_sats", -1):
        raise MintError("saved aggregate fee exceeds the plan cap")
    if total_gifts + total_fees > policy.get("max_total_spend_sats", -1):
        raise MintError("saved aggregate spend exceeds the plan cap")


def write_new_private_json(path: Path, value: dict[str, Any]) -> None:
    path = path.expanduser().resolve()
    path.parent.mkdir(parents=True, exist_ok=True)
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    try:
        descriptor = os.open(path, flags, 0o600)
    except FileExistsError as exc:
        raise MintError(f"refusing to overwrite existing plan: {path}") from exc
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
            json.dump(value, handle, indent=2, sort_keys=True)
            handle.write("\n")
            handle.flush()
            os.fsync(handle.fileno())
    except BaseException:
        try:
            path.unlink()
        except OSError:
            pass
        raise
    try:
        directory_fd = os.open(path.parent, os.O_RDONLY)
        try:
            os.fsync(directory_fd)
        finally:
            os.close(directory_fd)
    except BaseException:
        try:
            path.unlink()
        except OSError:
            pass
        raise


@contextmanager
def locked_plan(path: Path) -> Iterator[dict[str, Any]]:
    resolved = path.expanduser().resolve()
    try:
        mode = resolved.stat().st_mode & 0o777
    except OSError as exc:
        raise MintError(f"cannot stat plan {resolved}: {exc}") from exc
    if mode & 0o077:
        raise MintError("plan permissions must not allow group or world access")
    try:
        with resolved.open("r", encoding="utf-8") as handle:
            fcntl.flock(handle.fileno(), fcntl.LOCK_EX)
            plan = json.load(handle)
            if not isinstance(plan, dict):
                raise MintError("plan JSON must be an object")
            verify_plan(plan)
            yield plan
    except (OSError, json.JSONDecodeError) as exc:
        raise MintError(f"cannot read plan {resolved}: {exc}") from exc


def _require_dict(value: Any, description: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise MintError(f"{description} must be a JSON object")
    return value


def _decode_hex_field(
    value: Any, description: str, *, length: int | None = None
) -> bytes:
    if not isinstance(value, str) or value != value.lower():
        raise MintError(f"{description} must be lowercase hexadecimal")
    try:
        decoded = bytes.fromhex(value)
    except ValueError as exc:
        raise MintError(f"{description} must be lowercase hexadecimal") from exc
    if decoded.hex() != value:
        raise MintError(f"{description} must be canonical lowercase hexadecimal")
    if length is not None and len(decoded) != length:
        raise MintError(f"{description} must contain exactly {length} bytes")
    return decoded


def _require_exact_keys(
    value: dict[str, Any], *, required: set[str], optional: set[str], description: str
) -> None:
    missing = required - value.keys()
    unknown = value.keys() - required - optional
    if missing:
        raise MintError(f"{description} is missing: {', '.join(sorted(missing))}")
    if unknown:
        raise MintError(f"{description} has unknown fields: {', '.join(sorted(unknown))}")


def _parse_utc_timestamp(value: Any, description: str) -> datetime:
    if not isinstance(value, str) or not value.endswith("Z"):
        raise MintError(f"{description} must be an ISO-8601 UTC timestamp ending in Z")
    try:
        parsed = datetime.fromisoformat(value[:-1] + "+00:00")
    except ValueError as exc:
        raise MintError(f"{description} is not a valid timestamp") from exc
    if parsed.tzinfo != timezone.utc:
        parsed = parsed.astimezone(timezone.utc)
    return parsed


def execution_journal_path(plan_path: Path) -> Path:
    """Return the required sibling state journal for a saved plan."""
    resolved = plan_path.expanduser().resolve()
    return resolved.with_name(resolved.name + JOURNAL_SUFFIX)


def _journal_record_hash(record_without_hash: dict[str, Any]) -> str:
    return hashlib.blake2b(
        _canonical_json(record_without_hash), digest_size=32
    ).hexdigest()


def _validate_journal_inputs(value: Any, description: str) -> list[dict[str, Any]]:
    if not isinstance(value, list) or not value:
        raise MintError(f"{description} must contain at least one outpoint")
    normalized: list[dict[str, Any]] = []
    seen: set[tuple[str, int]] = set()
    for item in value:
        record = _require_dict(item, description)
        _require_exact_keys(
            record,
            required={"txid", "vout"},
            optional=set(),
            description=description,
        )
        txid = record.get("txid")
        vout = record.get("vout")
        _decode_hex_field(txid, f"{description} txid", length=32)
        if isinstance(vout, bool) or not isinstance(vout, int) or vout < 0:
            raise MintError(f"{description} vout is malformed")
        key = (txid, vout)
        if key in seen:
            raise MintError(f"{description} repeats an outpoint")
        seen.add(key)
        normalized.append({"txid": txid, "vout": vout})
    return normalized


class ExecutionJournal:
    """Mode-0600, append-only, hash-chained execution state.

    The plan contains immutable transactions.  This sibling journal records
    monotonic operational facts before the corresponding wallet/RPC action so
    that an evicted transaction can never make a prior send attempt look like
    an untouched plan.
    """

    _MAX_BYTES = 4 * 1024 * 1024
    _EVENT_FIELDS = {
        "HEADER": {
            "format",
            "schema_version",
            "reservation_id",
            "chain",
            "genesis",
            "wallet_name",
        },
        "INPUTS_SELECTED": {"entry", "inputs"},
        "LOCKS_PERSISTED": {"entry", "inputs"},
        "PLAN_COMMITTED": {"plan_id", "plan_checksum"},
        "FUNDING_ATTEMPTED": {"entry", "txid"},
        "FUNDING_OBSERVED": {"entry", "txid"},
        "SPEND_SELECTED": {"entry", "stage", "txid"},
        "SPEND_OBSERVED": {"entry", "stage", "txid"},
        "UNLOCK_INTENT": {"entry", "inputs"},
        "UNLOCKED": {"entry", "inputs"},
    }

    def __init__(self, descriptor: int, path: Path, records: list[dict[str, Any]]) -> None:
        self._descriptor = descriptor
        self.path = path
        self.records = records

    def __enter__(self) -> "ExecutionJournal":
        return self

    def __exit__(self, exc_type: Any, exc: Any, traceback: Any) -> None:
        self.close()

    def close(self) -> None:
        if self._descriptor >= 0:
            try:
                fcntl.flock(self._descriptor, fcntl.LOCK_UN)
            finally:
                os.close(self._descriptor)
                self._descriptor = -1

    @classmethod
    def create(
        cls,
        path: Path,
        *,
        reservation_id: str,
        chain: str,
        genesis: str,
        wallet_name: str,
    ) -> "ExecutionJournal":
        resolved = path.expanduser().resolve()
        resolved.parent.mkdir(parents=True, exist_ok=True)
        flags = os.O_RDWR | os.O_CREAT | os.O_EXCL | os.O_APPEND
        if hasattr(os, "O_NOFOLLOW"):
            flags |= os.O_NOFOLLOW
        try:
            descriptor = os.open(resolved, flags, 0o600)
        except FileExistsError as exc:
            raise MintError(f"refusing to overwrite existing journal: {resolved}") from exc
        journal = cls(descriptor, resolved, [])
        try:
            fcntl.flock(descriptor, fcntl.LOCK_EX)
            journal.append(
                "HEADER",
                format=JOURNAL_FORMAT,
                schema_version=JOURNAL_SCHEMA_VERSION,
                reservation_id=reservation_id,
                chain=chain,
                genesis=genesis,
                wallet_name=wallet_name,
            )
            directory_fd = os.open(resolved.parent, os.O_RDONLY)
            try:
                os.fsync(directory_fd)
            finally:
                os.close(directory_fd)
            return journal
        except BaseException:
            journal.close()
            try:
                resolved.unlink()
            except OSError:
                pass
            raise

    @classmethod
    def open(cls, path: Path) -> "ExecutionJournal":
        resolved = path.expanduser().resolve()
        flags = os.O_RDWR | os.O_APPEND
        if hasattr(os, "O_NOFOLLOW"):
            flags |= os.O_NOFOLLOW
        try:
            descriptor = os.open(resolved, flags)
        except OSError as exc:
            raise MintError(f"cannot open required execution journal {resolved}: {exc}") from exc
        try:
            fcntl.flock(descriptor, fcntl.LOCK_EX)
            metadata = os.fstat(descriptor)
            if (
                not stat.S_ISREG(metadata.st_mode)
                or metadata.st_mode & 0o077
                or metadata.st_nlink != 1
            ):
                raise MintError(
                    "execution journal must be one private regular file with no hard links"
                )
            if metadata.st_size <= 0 or metadata.st_size > cls._MAX_BYTES:
                raise MintError("execution journal has an invalid size")
            os.lseek(descriptor, 0, os.SEEK_SET)
            data = b""
            while len(data) < metadata.st_size:
                chunk = os.read(descriptor, metadata.st_size - len(data))
                if not chunk:
                    break
                data += chunk
            if len(data) != metadata.st_size or not data.endswith(b"\n"):
                raise MintError("execution journal is truncated")
            records: list[dict[str, Any]] = []
            for line_number, line in enumerate(data.splitlines(), start=1):
                try:
                    record = json.loads(line)
                except (UnicodeDecodeError, json.JSONDecodeError) as exc:
                    raise MintError(
                        f"execution journal line {line_number} is invalid JSON"
                    ) from exc
                if not isinstance(record, dict):
                    raise MintError(
                        f"execution journal line {line_number} is not an object"
                    )
                records.append(record)
            cls._validate_records(records)
            return cls(descriptor, resolved, records)
        except BaseException:
            try:
                fcntl.flock(descriptor, fcntl.LOCK_UN)
            finally:
                os.close(descriptor)
            raise

    @classmethod
    def _validate_records(cls, records: Sequence[dict[str, Any]]) -> None:
        if not records or records[0].get("event") != "HEADER":
            raise MintError("execution journal is missing its header")
        previous_hash = "0" * 64
        selected: dict[int, list[dict[str, Any]]] = {}
        persisted: set[int] = set()
        committed = False
        funding_irreversible: set[int] = set()
        spend_selected: dict[int, str] = {}
        unlock_intent: set[int] = set()
        unlocked: set[int] = set()
        for sequence, raw_record in enumerate(records):
            record = _require_dict(raw_record, "execution journal record")
            event = record.get("event")
            payload_fields = cls._EVENT_FIELDS.get(event)
            if payload_fields is None:
                raise MintError("execution journal contains an unknown event")
            _require_exact_keys(
                record,
                required={
                    "sequence",
                    "event",
                    "at",
                    "previous_hash",
                    "record_hash",
                    *payload_fields,
                },
                optional=set(),
                description=f"execution journal {event} record",
            )
            if isinstance(record.get("sequence"), bool) or record.get("sequence") != sequence:
                raise MintError("execution journal sequence is not monotonic")
            _parse_utc_timestamp(record.get("at"), "execution journal timestamp")
            if record.get("previous_hash") != previous_hash:
                raise MintError("execution journal hash chain is broken")
            claimed_hash = record.get("record_hash")
            unsigned = dict(record)
            unsigned.pop("record_hash", None)
            actual_hash = _journal_record_hash(unsigned)
            if (
                not isinstance(claimed_hash, str)
                or not hmac.compare_digest(claimed_hash, actual_hash)
            ):
                raise MintError("execution journal record hash does not match")
            previous_hash = claimed_hash

            if event == "HEADER":
                if sequence != 0:
                    raise MintError("execution journal header is not first")
                if (
                    record.get("format") != JOURNAL_FORMAT
                    or isinstance(record.get("schema_version"), bool)
                    or record.get("schema_version") != JOURNAL_SCHEMA_VERSION
                    or record.get("chain") not in {"main", "regtest"}
                    or not isinstance(record.get("wallet_name"), str)
                ):
                    raise MintError("execution journal header is malformed")
                _decode_hex_field(
                    record.get("reservation_id"),
                    "execution journal reservation id",
                    length=16,
                )
                _decode_hex_field(
                    record.get("genesis"), "execution journal genesis", length=32
                )
                continue

            entry = record.get("entry")
            if event not in {"PLAN_COMMITTED"}:
                if isinstance(entry, bool) or not isinstance(entry, int) or entry < 0:
                    raise MintError("execution journal entry index is malformed")
            if event in {
                "INPUTS_SELECTED",
                "LOCKS_PERSISTED",
                "UNLOCK_INTENT",
                "UNLOCKED",
            }:
                inputs = _validate_journal_inputs(
                    record.get("inputs"), f"execution journal {event} inputs"
                )
            if event == "INPUTS_SELECTED":
                if committed or entry in selected:
                    raise MintError("execution journal selected-input transition is invalid")
                selected[entry] = inputs
            elif event == "LOCKS_PERSISTED":
                if committed or entry not in selected or entry in persisted:
                    raise MintError("execution journal persistent-lock transition is invalid")
                if inputs != selected[entry]:
                    raise MintError("execution journal persistent locks changed")
                persisted.add(entry)
            elif event == "PLAN_COMMITTED":
                if committed or not selected or persisted != set(selected):
                    raise MintError("execution journal plan commit transition is invalid")
                _decode_hex_field(record.get("plan_id"), "journal plan id", length=16)
                _decode_hex_field(
                    record.get("plan_checksum"), "journal plan checksum", length=32
                )
                committed = True
            elif event in {"FUNDING_ATTEMPTED", "FUNDING_OBSERVED"}:
                if not committed or entry not in selected or entry in unlock_intent:
                    raise MintError("execution journal funding transition is invalid")
                _decode_hex_field(record.get("txid"), "journal funding txid", length=32)
                funding_irreversible.add(entry)
            elif event in {"SPEND_SELECTED", "SPEND_OBSERVED"}:
                stage = record.get("stage")
                if (
                    not committed
                    or entry not in selected
                    or entry in unlock_intent
                    or stage not in {"reveal", "refund"}
                    or entry in spend_selected
                ):
                    raise MintError("execution journal spend selection is invalid")
                _decode_hex_field(record.get("txid"), "journal spend txid", length=32)
                spend_selected[entry] = stage
                funding_irreversible.add(entry)
            elif event == "UNLOCK_INTENT":
                if (
                    not committed
                    or entry not in selected
                    or entry in funding_irreversible
                    or entry in unlock_intent
                ):
                    raise MintError("execution journal unlock transition is invalid")
                if inputs != selected[entry]:
                    raise MintError("execution journal unlock inputs changed")
                unlock_intent.add(entry)
            elif event == "UNLOCKED":
                if entry not in unlock_intent or entry in unlocked:
                    raise MintError("execution journal unlocked transition is invalid")
                if inputs != selected[entry]:
                    raise MintError("execution journal unlocked inputs changed")
                unlocked.add(entry)
        if not committed and len(records) > 1:
            # An incomplete preparation journal is intentionally readable for
            # exact manual recovery, but it cannot authorize plan execution.
            return

    def append(self, event: str, **payload: Any) -> None:
        if event not in self._EVENT_FIELDS:
            raise MintError("refusing to append an unknown journal event")
        previous_hash = (
            self.records[-1]["record_hash"] if self.records else "0" * 64
        )
        record = {
            "sequence": len(self.records),
            "event": event,
            "at": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
            "previous_hash": previous_hash,
            **payload,
        }
        record["record_hash"] = _journal_record_hash(record)
        candidate = [*self.records, record]
        self._validate_records(candidate)
        encoded = _canonical_json(record) + b"\n"
        if os.fstat(self._descriptor).st_size + len(encoded) > self._MAX_BYTES:
            raise MintError("execution journal would exceed its maximum size")
        written = 0
        while written < len(encoded):
            count = os.write(self._descriptor, encoded[written:])
            if count <= 0:
                raise MintError("failed to append the execution journal")
            written += count
        os.fsync(self._descriptor)
        self.records.append(record)

    def validate_for_plan(self, plan: dict[str, Any]) -> None:
        verify_plan(plan)
        header = self.records[0]
        reservation = plan["reservation"]
        snapshot = plan["chain_snapshot"]
        if (
            header["reservation_id"] != reservation["id"]
            or header["chain"] != snapshot["chain"]
            or header["genesis"] != snapshot["genesis"]
            or header["wallet_name"] != reservation["wallet_name"]
        ):
            raise MintError("execution journal does not belong to this plan")
        commits = [record for record in self.records if record["event"] == "PLAN_COMMITTED"]
        if len(commits) != 1 or (
            commits[0]["plan_id"] != plan["plan_id"]
            or commits[0]["plan_checksum"] != plan["checksum_blake2b256"]
        ):
            raise MintError("execution journal is not committed to this exact plan")
        expected = {
            entry["index"]: entry["funding"]["locked_wallet_inputs"]
            for entry in plan["entries"]
        }
        selected = {
            record["entry"]: record["inputs"]
            for record in self.records
            if record["event"] == "INPUTS_SELECTED"
        }
        persisted = {
            record["entry"]: record["inputs"]
            for record in self.records
            if record["event"] == "LOCKS_PERSISTED"
        }
        if selected != expected or persisted != expected:
            raise MintError("execution journal wallet inputs differ from the exact plan")
        for record in self.records:
            if "entry" in record and record["entry"] not in expected:
                raise MintError("execution journal refers to an unknown plan entry")
            if record["event"] in {"FUNDING_ATTEMPTED", "FUNDING_OBSERVED"}:
                if record["txid"] != plan["entries"][record["entry"]]["funding"]["txid"]:
                    raise MintError("journal funding txid differs from the exact plan")
            if record["event"] in {"SPEND_SELECTED", "SPEND_OBSERVED"}:
                entry = plan["entries"][record["entry"]]
                if record["txid"] != entry[record["stage"]]["txid"]:
                    raise MintError("journal spend txid differs from the exact plan")

    def _events(self, event: str, entry: int) -> list[dict[str, Any]]:
        return [
            record
            for record in self.records
            if record["event"] == event and record.get("entry") == entry
        ]

    def record_inputs_selected(
        self, entry: int, inputs: Sequence[dict[str, Any]]
    ) -> None:
        self.append("INPUTS_SELECTED", entry=entry, inputs=list(inputs))

    def record_locks_persisted(
        self, entry: int, inputs: Sequence[dict[str, Any]]
    ) -> None:
        self.append("LOCKS_PERSISTED", entry=entry, inputs=list(inputs))

    def commit_plan(self, plan: dict[str, Any]) -> None:
        self.append(
            "PLAN_COMMITTED",
            plan_id=plan["plan_id"],
            plan_checksum=plan["checksum_blake2b256"],
        )
        self.validate_for_plan(plan)

    def record_funding_irreversible(
        self, entry: int, txid: str, *, observed: bool = False
    ) -> None:
        existing = self._events("FUNDING_ATTEMPTED", entry) + self._events(
            "FUNDING_OBSERVED", entry
        )
        if existing:
            if any(record["txid"] != txid for record in existing):
                raise MintError("journal already records a different funding transaction")
            return
        self.append(
            "FUNDING_OBSERVED" if observed else "FUNDING_ATTEMPTED",
            entry=entry,
            txid=txid,
        )

    def select_spend(self, entry: int, stage: str, txid: str) -> None:
        existing = self._events("SPEND_SELECTED", entry) + self._events(
            "SPEND_OBSERVED", entry
        )
        if existing:
            selected = existing[0]
            if selected["stage"] != stage or selected["txid"] != txid:
                raise MintError(
                    f"journal permanently selected {selected['stage']} for entry {entry}"
                )
            return
        self.append("SPEND_SELECTED", entry=entry, stage=stage, txid=txid)

    def observe_spend(self, entry: int, stage: str, txid: str) -> None:
        existing = self._events("SPEND_SELECTED", entry) + self._events(
            "SPEND_OBSERVED", entry
        )
        if existing:
            selected = existing[0]
            if selected["stage"] != stage or selected["txid"] != txid:
                raise MintError(
                    f"journal permanently selected {selected['stage']} for entry {entry}"
                )
            return
        self.append("SPEND_OBSERVED", entry=entry, stage=stage, txid=txid)

    def unlock_state(self, entry: int) -> str:
        if self._events("UNLOCKED", entry):
            return "unlocked"
        if self._events("UNLOCK_INTENT", entry):
            return "intent"
        irreversible = any(
            self._events(event, entry)
            for event in (
                "FUNDING_ATTEMPTED",
                "FUNDING_OBSERVED",
                "SPEND_SELECTED",
                "SPEND_OBSERVED",
            )
        )
        return "blocked" if irreversible else "available"

    def begin_unlock(self, entry: int, inputs: Sequence[dict[str, Any]]) -> None:
        state = self.unlock_state(entry)
        if state == "blocked":
            raise MintError(
                f"entry {entry} can never be auto-unlocked after a recorded broadcast/observation"
            )
        if state == "unlocked":
            return
        if state == "available":
            self.append("UNLOCK_INTENT", entry=entry, inputs=list(inputs))

    def finish_unlock(self, entry: int, inputs: Sequence[dict[str, Any]]) -> None:
        if self.unlock_state(entry) == "unlocked":
            return
        self.append("UNLOCKED", entry=entry, inputs=list(inputs))


def load_consent_records(
    path: Path,
    *,
    chain: str,
    artifact_digest: str,
    now: datetime | None = None,
) -> list[dict[str, Any]]:
    """Load strict, artifact-bound self/consent-reference recipient records."""
    try:
        raw = json.loads(path.expanduser().read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise MintError(f"cannot read recipient file {path}: {exc}") from exc
    document = _require_dict(raw, "recipient file")
    _require_exact_keys(
        document,
        required={"schema", "chain", "artifact_blake2b256", "entries"},
        optional=set(),
        description="recipient file",
    )
    if document["schema"] != "bordinals-consent/1":
        raise MintError("recipient file schema must be bordinals-consent/1")
    if document["chain"] != chain:
        raise MintError("recipient file chain does not match the requested chain")
    if document["artifact_blake2b256"] != artifact_digest:
        raise MintError("recipient consent is bound to a different artifact digest")
    entries = document["entries"]
    if not isinstance(entries, list) or not 1 <= len(entries) <= MAX_RECIPIENTS:
        raise MintError(f"recipient file must contain 1..{MAX_RECIPIENTS} entries")

    current = now or datetime.now(timezone.utc)
    recipients: list[dict[str, Any]] = []
    seen_addresses: set[str] = set()
    seen_references: set[str] = set()
    for index, raw_entry in enumerate(entries):
        entry = _require_dict(raw_entry, f"recipient entry {index}")
        _require_exact_keys(
            entry,
            required={"address", "gift_sats", "consent"},
            optional={"label"},
            description=f"recipient entry {index}",
        )
        address = entry["address"]
        if not isinstance(address, str) or not address or address != address.strip():
            raise MintError(f"recipient entry {index} has an invalid or padded address")
        if address in seen_addresses:
            raise MintError(f"recipient entry {index} duplicates an address")
        seen_addresses.add(address)
        gift_sats = entry["gift_sats"]
        if isinstance(gift_sats, bool) or not isinstance(gift_sats, int) or gift_sats <= 0:
            raise MintError(f"recipient entry {index} gift_sats must be a positive integer")
        if gift_sats > MAX_MONEY_SATS:
            raise MintError(f"recipient entry {index} gift_sats is outside the money range")
        label = entry.get("label", "")
        if not isinstance(label, str) or len(label) > 120:
            raise MintError(f"recipient entry {index} label must be at most 120 characters")

        consent = _require_dict(entry["consent"], f"recipient entry {index} consent")
        mode = consent.get("mode")
        if mode == "self":
            _require_exact_keys(
                consent,
                required={"mode"},
                optional=set(),
                description=f"recipient entry {index} consent",
            )
            normalized_consent = {"mode": "self"}
        elif mode == "reference":
            _require_exact_keys(
                consent,
                required={"mode", "reference", "obtained_at", "expires_at"},
                optional=set(),
                description=f"recipient entry {index} consent",
            )
            reference = consent["reference"]
            if (
                not isinstance(reference, str)
                or not reference.strip()
                or len(reference) > 500
            ):
                raise MintError(
                    f"recipient entry {index} consent reference must be 1..500 characters"
                )
            if reference in seen_references:
                raise MintError(f"recipient entry {index} duplicates a consent reference")
            seen_references.add(reference)
            obtained = _parse_utc_timestamp(
                consent["obtained_at"], f"recipient entry {index} obtained_at"
            )
            expires = _parse_utc_timestamp(
                consent["expires_at"], f"recipient entry {index} expires_at"
            )
            if obtained > current.replace(microsecond=0):
                raise MintError(f"recipient entry {index} consent is dated in the future")
            if expires <= current:
                raise MintError(f"recipient entry {index} consent has expired")
            if expires <= obtained:
                raise MintError(f"recipient entry {index} consent expiry precedes consent")
            normalized_consent = dict(consent)
        else:
            raise MintError(f"recipient entry {index} consent mode must be self or reference")
        recipients.append(
            {
                "address": address,
                "gift_sats": gift_sats,
                "label": label,
                "consent": normalized_consent,
            }
        )
    return recipients


def validate_p2tr_address(
    rpc: RPC, address: str, *, check_wallet: bool = False
) -> tuple[bytes, bool]:
    """Decode an exact P2TR address, optionally proving wallet ownership."""
    result = _require_dict(rpc.call("validateaddress", address), "validateaddress result")
    if not result.get("isvalid"):
        raise MintError(f"recipient is not valid for the connected network: {address}")
    if result.get("address") != address:
        raise MintError("recipient address does not round-trip canonically")
    if result.get("witness_version") != 1:
        raise MintError("recipient must be a native witness-v1 Taproot address")
    witness_program = result.get("witness_program")
    script_hex = result.get("scriptPubKey")
    if not isinstance(witness_program, str) or len(witness_program) != 64:
        raise MintError("recipient must contain a 32-byte Taproot witness program")
    if not isinstance(script_hex, str) or script_hex.lower() != "5120" + witness_program.lower():
        raise MintError("recipient must decode to an exact P2TR scriptPubKey")
    try:
        script = bytes.fromhex(script_hex)
    except ValueError as exc:
        raise MintError("recipient scriptPubKey is malformed") from exc
    is_mine = False
    if check_wallet:
        info = _require_dict(rpc.call("getaddressinfo", address), "getaddressinfo result")
        is_mine = bool(info.get("ismine"))
    return script, is_mine


def _dust_threshold_sats(rpc: RPC, script_pubkey: bytes) -> int:
    info = _require_dict(rpc.call("getmempoolinfo"), "getmempoolinfo result")
    try:
        sats_per_kvb = Decimal(str(info["dustrelayfee"])) * SATOSHIS
    except (KeyError, InvalidOperation) as exc:
        raise MintError("node did not report a valid dustrelayfee") from exc
    # Knots uses 67 discounted bytes for every witness-program spend.
    txout_size = 8 + len(compact_size(len(script_pubkey))) + len(script_pubkey)
    size = txout_size + 67
    return max(1, int((sats_per_kvb * size / 1000).to_integral_value(rounding=ROUND_CEILING)))


def inspect_chain_identity(
    rpc: RPC, expected_chain: str, *, require_fresh: bool = False
) -> dict[str, Any]:
    """Identify the saved chain without depending on a wallet or RDTS policy.

    Recovery and status deliberately use this narrower gate.  A signed refund
    must remain usable after consent or RDTS expires and after the operator
    upgrades Knots.  Mainnet's activation checkpoint distinguishes the
    BLAKE2b/RDTS chain without pinning the current node release.
    """
    if expected_chain not in {"main", "regtest"}:
        raise MintError("this experimental minter supports only main and regtest")
    blockchain = _require_dict(rpc.call("getblockchaininfo"), "getblockchaininfo result")
    if blockchain.get("chain") != expected_chain:
        raise MintError(
            f"connected chain {blockchain.get('chain')!r} does not match {expected_chain!r}"
        )
    if blockchain.get("initialblockdownload") is not False:
        raise MintError("node is still in initial block download")
    blocks = blockchain.get("blocks")
    headers = blockchain.get("headers")
    if not isinstance(blocks, int) or not isinstance(headers, int) or headers - blocks > 2:
        raise MintError("node is too far behind its reported headers")
    best = blockchain.get("bestblockhash")
    if not isinstance(best, str) or len(best) != 64:
        raise MintError("node returned an invalid best block hash")
    genesis = rpc.call("getblockhash", 0)
    expected_genesis = MAINNET_GENESIS if expected_chain == "main" else REGTEST_GENESIS
    if genesis != expected_genesis:
        raise MintError("connected chain has an unexpected genesis block")
    if expected_chain == "main":
        if blocks < 961_640:
            raise MintError("mainnet is below the BLAKE2b/RDTS activation height")
        checkpoint = rpc.call("getblockhash", 961_640)
        if checkpoint != "0000000000000050c1e5f69672f459293be14f46e5a494e7a8c8541396f18eeb":
            raise MintError("mainnet BLAKE2b activation checkpoint does not match")
        if require_fresh:
            tip_time = blockchain.get("time")
            wall_time = int(datetime.now(timezone.utc).timestamp())
            if (
                isinstance(tip_time, bool)
                or not isinstance(tip_time, int)
                or wall_time - tip_time > 6 * 60 * 60
                or tip_time - wall_time > 2 * 60 * 60
            ):
                raise MintError("mainnet tip is stale or implausibly far in the future")
            network = _require_dict(
                rpc.call("getnetworkinfo"), "getnetworkinfo result"
            )
            connections = network.get("connections")
            outbound = network.get("connections_out")
            if (
                network.get("networkactive") is not True
                or isinstance(connections, bool)
                or not isinstance(connections, int)
                or connections <= 0
                or isinstance(outbound, bool)
                or not isinstance(outbound, int)
                or outbound <= 0
            ):
                raise MintError("mainnet execution requires active networking and an outbound peer")
            if network.get("warnings") not in (None, "", []):
                raise MintError("mainnet node reports a warning; resolve it before execution")
    return {
        "chain": expected_chain,
        "genesis": genesis,
        "bestblockhash": best,
        "blocks": blocks,
        "mediantime": blockchain.get("mediantime"),
    }


def inspect_node(
    rpc: RPC,
    expected_chain: str,
    *,
    require_headroom: bool,
    require_wallet: bool = True,
) -> dict[str, Any]:
    """Fail closed unless this is the pinned latest-Knots minting profile."""
    identity = inspect_chain_identity(rpc, expected_chain, require_fresh=True)
    best = identity["bestblockhash"]
    blocks = identity["blocks"]
    median_time = identity["mediantime"]

    network = _require_dict(rpc.call("getnetworkinfo"), "getnetworkinfo result")
    version = network.get("version")
    subversion = network.get("subversion")
    if expected_chain == "main":
        if version != 290401 or not isinstance(subversion, str) or "/Knots:20260508/" not in subversion:
            raise MintError(
                "mainnet minting is pinned to Bitcoin Knots v29.4.1.knots20260508"
            )
    elif not isinstance(subversion, str) or "Knots:" not in subversion:
        raise MintError("connected node does not identify as Bitcoin Knots")

    deployment = _require_dict(
        rpc.call("getdeploymentinfo", best), "getdeploymentinfo result"
    )
    blake2b = _require_dict(deployment.get("blake2b"), "blake2b deployment")
    reduced = _require_dict(
        _require_dict(deployment.get("deployments"), "deployments").get("reduced_data"),
        "reduced_data deployment",
    )
    if blake2b.get("active") is not True:
        raise MintError("BLAKE2b fork rules are not active for the next block")
    if reduced.get("active") is not True:
        raise MintError("BIP-110/RDTS rules are not active for the next block")
    expiry = reduced.get("expiry_time")
    if not isinstance(expiry, int) or not isinstance(median_time, int):
        raise MintError("node did not report RDTS expiry and median time")
    effective_time = max(
        median_time,
        int(datetime.now(timezone.utc).timestamp()) if expected_chain == "main" else median_time,
    )
    if effective_time >= expiry:
        raise MintError("BIP-110/RDTS has expired at the current chain tip")
    if require_headroom and expiry - effective_time < 7 * 24 * 60 * 60:
        raise MintError("less than seven days of RDTS median-time headroom remain")

    header = _require_dict(rpc.call("getblockheader", best), "getblockheader result")
    if header.get("header_version") != 2:
        raise MintError("best Knots block does not use the expected v2 header")
    if expected_chain == "main":
        if blake2b.get("height") != 961_640:
            raise MintError("unexpected mainnet BLAKE2b activation height")
        if reduced.get("height") != 961_640 or expiry != 1_819_756_800:
            raise MintError("unexpected mainnet RDTS activation or expiry parameters")

    if require_wallet:
        wallet = _require_dict(rpc.call("getwalletinfo"), "getwalletinfo result")
        if wallet.get("private_keys_enabled") is not True:
            raise MintError("funding wallet has private keys disabled")
        if wallet.get("scanning") not in (False, None):
            raise MintError("funding wallet is currently scanning")
    return {
        **identity,
        "node_version": version,
        "subversion": subversion,
        "blake2b": blake2b,
        "reduced_data": {
            "height": reduced.get("height"),
            "expiry_time": expiry,
            "active": True,
        },
    }


BECH32_CHARSET = "qpzry9x8gf2tvdw0s3jn54khce6mua7l"


def _bech32_polymod(values: Sequence[int]) -> int:
    generators = (0x3B6A57B2, 0x26508E6D, 0x1EA119FA, 0x3D4233DD, 0x2A1462B3)
    checksum = 1
    for value in values:
        top = checksum >> 25
        checksum = ((checksum & 0x1FFFFFF) << 5) ^ value
        for bit, generator in enumerate(generators):
            if (top >> bit) & 1:
                checksum ^= generator
    return checksum


def _bech32_hrp_expand(hrp: str) -> list[int]:
    return [ord(char) >> 5 for char in hrp] + [0] + [ord(char) & 31 for char in hrp]


def _convert_bits(data: bytes, from_bits: int, to_bits: int) -> list[int]:
    accumulator = 0
    bits = 0
    result: list[int] = []
    maximum = (1 << to_bits) - 1
    for value in data:
        if value >> from_bits:
            raise MintError("value exceeds source bit width")
        accumulator = (accumulator << from_bits) | value
        bits += from_bits
        while bits >= to_bits:
            bits -= to_bits
            result.append((accumulator >> bits) & maximum)
    if bits:
        result.append((accumulator << (to_bits - bits)) & maximum)
    return result


def p2wsh_address(script: bytes, chain: str) -> str:
    hrp = {"main": "bc", "regtest": "bcrt"}.get(chain)
    if hrp is None:
        raise MintError("unsupported address network")
    data = [0, *_convert_bits(sha256(script), 8, 5)]
    values = _bech32_hrp_expand(hrp) + data + [0] * 6
    polymod = _bech32_polymod(values) ^ 1
    checksum = [(polymod >> (5 * (5 - index))) & 31 for index in range(6)]
    return hrp + "1" + "".join(BECH32_CHARSET[item] for item in data + checksum)


def _distribute_sats(total: int, count: int, minimum: int) -> list[int]:
    base, remainder = divmod(total, count)
    if base < minimum:
        shortfall = count * minimum - total
        raise MintError(
            f"carrier outputs would be dust; increase gift_sats by at least {shortfall}"
        )
    return [base + (1 if index < remainder else 0) for index in range(count)]


def _new_carrier_key_and_scripts(content: bytes) -> tuple[int, bytes, list[bytes]]:
    payloads = encode_payloads(content)
    while True:
        secret = secrets.randbelow(SECP256K1_N - 1) + 1
        pubkey = compressed_pubkey(secret)
        try:
            scripts = [
                build_script(payload, pubkey, carrier_index=index)
                for index, payload in enumerate(payloads)
            ]
            for script in scripts:
                p2wsh_scriptpubkey(script)
        except ValueError:
            # The only expected retry is the astronomically rare conservative
            # OLGA-prefix rejection.  A fresh key changes every program.
            continue
        return secret, pubkey, scripts


def _funding_signature_types_are_unified(transaction: Transaction) -> bool:
    for txin in transaction.inputs:
        if not txin.witness:
            return False
        found = False
        first = txin.witness[0]
        if len(txin.witness) == 1 and len(first) == 65:
            if first[-1] != BORDINALS_SIGHASH:
                return False
            continue
        for item in txin.witness[:-1] if len(txin.witness) > 1 else txin.witness:
            if 9 <= len(item) <= 73 and item[:1] == b"\x30":
                try:
                    validate_signature_item(item)
                except ValueError:
                    return False
                found = True
        if not found:
            return False
    return True


def _is_native_witness_scriptpubkey(script: bytes) -> bool:
    if len(script) < 4 or len(script) != script[1] + 2:
        return False
    version = script[0]
    program_length = script[1]
    if version == 0:
        return program_length in {20, 32}
    return 0x51 <= version <= 0x60 and 2 <= program_length <= 40


def _locked_intersection(rpc: RPC, outpoints: Sequence[dict[str, Any]]) -> list[dict[str, Any]]:
    current = {
        (item.get("txid"), item.get("vout"))
        for item in rpc.call("listlockunspent")
        if isinstance(item, dict)
    }
    return [
        {"txid": item["txid"], "vout": item["vout"]}
        for item in outpoints
        if (item.get("txid"), item.get("vout")) in current
    ]


def _canonical_outpoints(
    outpoints: Sequence[dict[str, Any]],
) -> list[dict[str, Any]]:
    """Copy and deduplicate exact outpoints without broadening their scope."""
    normalized: list[dict[str, Any]] = []
    seen: set[tuple[str, int]] = set()
    for item in outpoints:
        if not isinstance(item, dict):
            raise MintError("wallet-lock outpoint is malformed")
        txid = item.get("txid")
        vout = item.get("vout")
        _decode_hex_field(txid, "wallet-lock txid", length=32)
        if isinstance(vout, bool) or not isinstance(vout, int) or vout < 0:
            raise MintError("wallet-lock vout is malformed")
        key = (txid, vout)
        if key not in seen:
            seen.add(key)
            normalized.append({"txid": txid, "vout": vout})
    return normalized


def _unlock_exact_wallet_inputs(
    rpc: RPC, outpoints: Sequence[dict[str, Any]]
) -> list[dict[str, Any]]:
    """Unlock only the named inputs that are still locked by this wallet."""
    unlocked: list[dict[str, Any]] = []
    candidates = _canonical_outpoints(outpoints)
    for outpoint in _locked_intersection(rpc, candidates):
        if not _locked_intersection(rpc, [outpoint]):
            continue
        try:
            result = rpc.call("lockunspent", True, [outpoint], True)
        except BaseException:
            # A concurrent wallet process may have unlocked the exact coin
            # after our probe, or the RPC response may have been lost after
            # Knots committed the change. Reconcile before deciding it failed.
            if not _locked_intersection(rpc, [outpoint]):
                unlocked.append(outpoint)
                continue
            raise
        if result is not True:
            raise MintError("wallet did not unlock a selected plan input")
        if _locked_intersection(rpc, [outpoint]):
            raise MintError("wallet reported success but retained a selected input lock")
        unlocked.append(outpoint)
    return unlocked


def _cleanup_reserved_after_failure(
    rpc: RPC,
    outpoints: Sequence[dict[str, Any]],
    primary: BaseException,
) -> None:
    """Best-effort exact cleanup that never hides an uncertain persistent lock."""
    candidates = _canonical_outpoints(outpoints)
    if not candidates:
        return
    cleanup_error: BaseException | None = None
    try:
        _unlock_exact_wallet_inputs(rpc, candidates)
    except BaseException as exc:
        cleanup_error = exc
    try:
        remaining = _locked_intersection(rpc, candidates)
    except BaseException as exc:
        if cleanup_error is None:
            cleanup_error = exc
        raise LockCleanupError(primary, candidates, None, cleanup_error) from primary
    if remaining:
        raise LockCleanupError(primary, candidates, remaining, cleanup_error) from primary


def _wallet_fund_and_sign(
    rpc: RPC,
    outputs: list[dict[str, Any]],
    fee_rate: Decimal,
    *,
    before_persistent_lock: Callable[[Sequence[dict[str, Any]]], None] | None = None,
    after_persistent_lock: Callable[[Sequence[dict[str, Any]]], None] | None = None,
) -> tuple[str, int, list[dict[str, Any]], dict[str, Any] | None]:
    change_address = rpc.call("getrawchangeaddress", "bech32m")
    if not isinstance(change_address, str):
        raise MintError("wallet did not return a P2TR change address")
    change_script, change_is_mine = validate_p2tr_address(
        rpc, change_address, check_wallet=True
    )
    if not change_is_mine:
        raise MintError("wallet-provided change address is not wallet-owned")
    options = {
        "add_inputs": True,
        "include_unsafe": False,
        "minconf": 1,
        "lockUnspents": True,
        "replaceable": False,
        "fee_rate": float(fee_rate),
        "change_address": change_address,
        "segwit_inputs_only": True,
        "max_tx_weight": 400_000,
    }
    selected: list[dict[str, Any]] = []
    try:
        funded = _require_dict(
            rpc.call("walletcreatefundedpsbt", [], outputs, 0, options, True),
            "walletcreatefundedpsbt result",
        )
        psbt = funded.get("psbt")
        if not isinstance(psbt, str):
            raise MintError("walletcreatefundedpsbt did not return a PSBT")
        decoded_psbt = _require_dict(rpc.call("decodepsbt", psbt), "decodepsbt result")
        unsigned = _require_dict(decoded_psbt.get("tx"), "decoded PSBT transaction")
        for vin in unsigned.get("vin", []):
            if (
                not isinstance(vin, dict)
                or not isinstance(vin.get("txid"), str)
                or isinstance(vin.get("vout"), bool)
                or not isinstance(vin.get("vout"), int)
            ):
                raise MintError("funding PSBT contains a malformed input")
            selected.append({"txid": vin["txid"], "vout": vin["vout"]})
        if not selected:
            raise MintError("wallet selected no funding inputs")
        psbt_inputs = decoded_psbt.get("inputs")
        if not isinstance(psbt_inputs, list) or len(psbt_inputs) != len(selected):
            raise MintError("decoded funding PSBT omitted its input metadata")
        for psbt_input in psbt_inputs:
            metadata = _require_dict(psbt_input, "funding PSBT input metadata")
            witness_utxo = _require_dict(
                metadata.get("witness_utxo"), "funding PSBT witness UTXO"
            )
            script_info = _require_dict(
                witness_utxo.get("scriptPubKey"), "funding PSBT prevout scriptPubKey"
            )
            prevout_script = _decode_hex_field(
                script_info.get("hex"), "funding PSBT prevout scriptPubKey"
            )
            if not _is_native_witness_scriptpubkey(prevout_script):
                raise MintError(
                    "funding inputs must be native SegWit; wrapped P2SH-SegWit is refused"
                )
        processed = _require_dict(
            rpc.call(
                "walletprocesspsbt",
                psbt,
                {
                    "sign": True,
                    "sighashtype": "ALL|UNIFIED",
                    "bip32derivs": True,
                    "finalize": True,
                },
            ),
            "walletprocesspsbt result",
        )
        if processed.get("complete") is not True or not isinstance(processed.get("hex"), str):
            raise MintError(
                "wallet could not finalize funding with ALL|UNIFIED; check wallet lock and -walletoldsigs"
            )
        funding_hex = processed["hex"]
        funding_tx = parse_transaction(funding_hex)
        if unsigned.get("txid") != funding_tx.txid:
            raise MintError("wallet signed a different funding transaction than its PSBT")
        if not _funding_signature_types_are_unified(funding_tx):
            raise MintError("not every funding input carries an explicit unified signature")

        change_pos = funded.get("changepos")
        if isinstance(change_pos, bool) or not isinstance(change_pos, int):
            raise MintError("walletcreatefundedpsbt returned an invalid change position")
        change: dict[str, Any] | None = None
        if change_pos != -1:
            if not 0 <= change_pos < len(funding_tx.outputs):
                raise MintError("wallet change position is outside the funding transaction")
            decoded = _require_dict(
                rpc.call("decoderawtransaction", funding_hex),
                "decoded signed funding transaction",
            )
            decoded_outputs = decoded.get("vout")
            if not isinstance(decoded_outputs, list) or change_pos >= len(decoded_outputs):
                raise MintError("decoded funding transaction omitted wallet change")
            change_output = _require_dict(
                decoded_outputs[change_pos], "decoded wallet change output"
            )
            script_info = _require_dict(
                change_output.get("scriptPubKey"), "wallet change scriptPubKey"
            )
            address = script_info.get("address")
            if address != change_address:
                raise MintError("wallet used a different change address than requested")
            address_info = _require_dict(
                rpc.call("getaddressinfo", address), "wallet change getaddressinfo result"
            )
            if (
                address_info.get("ismine") is not True
                or address_info.get("solvable") is not True
                or address_info.get("iswatchonly") is True
            ):
                raise MintError("wallet change output is not wallet-owned and solvable")
            parsed_output = funding_tx.outputs[change_pos]
            if (
                script_info.get("hex") != parsed_output.script_pubkey.hex()
                or parsed_output.script_pubkey != change_script
            ):
                raise MintError("wallet change script differs from the signed transaction")
            change = {
                "vout": change_pos,
                "address": address,
                "script_pubkey": parsed_output.script_pubkey.hex(),
                "value_sats": parsed_output.value_sats,
            }

        # Journal the exact selected inputs before promoting the memory-only
        # wallet reservation into durable wallet state.
        if before_persistent_lock is not None:
            before_persistent_lock(selected)
        # walletcreatefundedpsbt's lockUnspents lock is memory-only. Knots
        # explicitly permits promoting an already-locked coin to a persistent
        # wallet-database lock with the third argument set to true.
        if rpc.call("lockunspent", False, selected, True) is not True:
            raise MintError("wallet did not persist every selected funding-input lock")
        if after_persistent_lock is not None:
            after_persistent_lock(selected)
        return funding_hex, btc_to_sats(funded.get("fee")), selected, change
    except BaseException as exc:
        if selected:
            _cleanup_reserved_after_failure(rpc, selected, exc)
        raise


def _assert_funding_shape(
    funding: Transaction,
    scripts: Sequence[bytes],
    carrier_values: Sequence[int],
    manifest: bytes,
    change: dict[str, Any] | None,
) -> list[int]:
    if len(scripts) != len(carrier_values):
        raise AssertionError("carrier script/value count mismatch")
    carrier_vouts: list[int] = []
    selected: set[int] = set()
    for script, value in zip(scripts, carrier_values, strict=True):
        wanted = p2wsh_scriptpubkey(script)
        matches = [
            index
            for index, output in enumerate(funding.outputs)
            if output.script_pubkey == wanted and output.value_sats == value
        ]
        if len(matches) != 1 or matches[0] in selected:
            raise MintError("signed funding changed or duplicated a carrier output")
        selected.add(matches[0])
        carrier_vouts.append(matches[0])
    manifest_script = op_return_script(manifest)
    manifest_matches = [
        index
        for index, output in enumerate(funding.outputs)
        if output.script_pubkey == manifest_script and output.value_sats == 0
    ]
    if len(manifest_matches) != 1:
        raise MintError("funding must contain one byte-identical zero-valued manifest")
    selected.add(manifest_matches[0])
    unplanned = set(range(len(funding.outputs))) - selected
    if change is None:
        if unplanned:
            raise MintError("wallet added an unrecorded funding output")
    else:
        if not isinstance(change, dict):
            raise MintError("saved wallet change metadata is malformed")
        _require_exact_keys(
            change,
            required={"vout", "address", "script_pubkey", "value_sats"},
            optional=set(),
            description="saved wallet change",
        )
        change_vout = change.get("vout")
        if (
            isinstance(change_vout, bool)
            or not isinstance(change_vout, int)
            or not 0 <= change_vout < len(funding.outputs)
        ):
            raise MintError("saved wallet change position is malformed")
        if unplanned != {change_vout}:
            raise MintError("wallet change position does not match the signed funding")
        output = funding.outputs[change_vout]
        change_script = _decode_hex_field(
            change.get("script_pubkey"), "saved wallet change scriptPubKey", length=34
        )
        if change_script[:2] != b"\x51\x20":
            raise MintError("saved wallet change scriptPubKey is not exact P2TR")
        if not isinstance(change.get("address"), str) or not change["address"]:
            raise MintError("saved wallet change address is malformed")
        if (
            isinstance(change.get("value_sats"), bool)
            or not isinstance(change.get("value_sats"), int)
            or change["value_sats"] <= 0
        ):
            raise MintError("saved wallet change value is malformed")
        if (
            output.value_sats != change.get("value_sats")
            or output.script_pubkey != change_script
        ):
            raise MintError("wallet change output differs from the saved plan")
    return carrier_vouts


def _build_unsigned_spend(
    funding_txid: str,
    carrier_vouts: Sequence[int],
    outputs: Sequence[TxOutput],
) -> Transaction:
    try:
        txid_le = bytes.fromhex(funding_txid)[::-1]
    except ValueError as exc:
        raise MintError("funding txid is malformed") from exc
    return Transaction(
        version=2,
        inputs=[TxInput(txid_le, vout, sequence=0xFFFFFFFD) for vout in carrier_vouts],
        outputs=list(outputs),
        locktime=0,
    )


def _assert_carrier_spend(
    transaction: Transaction,
    funding: Transaction,
    carrier_vouts: Sequence[int],
    scripts: Sequence[bytes],
    expected_outputs: Sequence[TxOutput],
    content: bytes,
    manifest: bytes | None,
) -> None:
    if transaction.outputs != list(expected_outputs):
        raise MintError("carrier spend outputs differ from the approved plan")
    if len(transaction.inputs) != len(scripts):
        raise MintError("carrier spend has an unexpected input count")
    for index, (txin, vout, script) in enumerate(
        zip(transaction.inputs, carrier_vouts, scripts, strict=True)
    ):
        if txin.prev_txid != funding.txid or txin.prev_vout != vout:
            raise MintError("carrier spend outpoints are not in canonical order")
        if txin.script_sig or txin.sequence != 0xFFFFFFFD:
            raise MintError("carrier spend input framing changed")
        if len(txin.witness) != 2 or txin.witness[1] != script:
            raise MintError("carrier witness must be exactly [signature, witnessScript]")
        validate_signature_item(txin.witness[0])
        if p2wsh_scriptpubkey(script) != funding.outputs[vout].script_pubkey:
            raise MintError(f"carrier witnessScript {index} does not match its prevout")
        witness_size = (
            len(compact_size(2))
            + len(varbytes(txin.witness[0]))
            + len(varbytes(script))
        )
        if witness_size > MAX_DEFAULT_WITNESS_BYTES:
            raise MintError("carrier witness exceeds Knots' audited policy limit")
    if transaction.weight > 400_000:
        raise MintError("carrier spend exceeds the standard transaction weight limit")
    if manifest is not None:
        recovered = decode_committed_witnesses(
            manifest, manifest, [item.witness for item in transaction.inputs]
        )
        if recovered != content:
            raise MintError("signed reveal does not reconstruct the approved artifact")


def _assert_preflight(
    rpc: RPC,
    raw_transactions: Sequence[str],
    expected_fees: Sequence[int],
    max_fee_rate: Decimal,
    description: str,
) -> list[dict[str, Any]]:
    try:
        result = rpc.call(
            "testmempoolaccept",
            list(raw_transactions),
            fee_rate_limit_btc_kvb(max_fee_rate),
            [],
        )
    except MintError as exc:
        raise MintError(f"{description} package preflight failed: {exc}") from exc
    if not isinstance(result, list) or len(result) != len(raw_transactions):
        raise MintError(f"{description} preflight returned an unexpected result")
    normalized: list[dict[str, Any]] = []
    for index, (item, raw, expected_fee) in enumerate(
        zip(result, raw_transactions, expected_fees, strict=True)
    ):
        if not isinstance(item, dict):
            raise MintError(f"{description} preflight item {index} is malformed")
        local = parse_transaction(raw)
        if item.get("txid") != local.txid or item.get("wtxid") != local.wtxid:
            raise MintError(f"{description} preflight returned a different transaction id")
        if item.get("allowed") is not True:
            reason = item.get("reject-reason") or item.get("package-error") or "not fully validated"
            raise MintError(f"{description} preflight rejected transaction {index}: {reason}")
        try:
            base_fee = btc_to_sats(item["fees"]["base"])
        except (KeyError, TypeError) as exc:
            raise MintError(f"{description} preflight omitted the base fee") from exc
        if base_fee != expected_fee:
            raise MintError(
                f"{description} preflight fee {base_fee} differs from expected {expected_fee}"
            )
        normalized.append(
            {
                "txid": local.txid,
                "wtxid": local.wtxid,
                "vsize": item.get("vsize"),
                "fee_sats": base_fee,
            }
        )
    return normalized


def _new_refund_address(rpc: RPC) -> tuple[str, bytes]:
    address = rpc.call("getnewaddress", "BORDINALS emergency refund", "bech32m")
    if not isinstance(address, str):
        raise MintError("wallet did not return an emergency refund address")
    script, is_mine = validate_p2tr_address(rpc, address, check_wallet=True)
    info = _require_dict(rpc.call("getaddressinfo", address), "refund getaddressinfo result")
    if not is_mine or info.get("solvable") is not True:
        raise MintError("emergency refund address is not wallet-owned and solvable")
    return address, script


def _validate_prepare_parameters(
    *,
    content: Any,
    artifact_name: Any,
    mime: Any,
    recipients: Any,
    chain: Any,
    fee_rate: Any,
    max_fee_rate: Any,
    max_carriers: Any,
    caps: dict[str, Any],
) -> int:
    if not isinstance(content, bytes) or not content:
        raise MintError("artifact must contain at least one byte")
    if not isinstance(artifact_name, str) or not artifact_name:
        raise MintError("artifact name must be a nonempty string")
    if not isinstance(mime, str):
        raise MintError("artifact MIME type must be a string")
    if not isinstance(recipients, (list, tuple)) or not 1 <= len(recipients) <= MAX_RECIPIENTS:
        raise MintError(f"prepare requires 1..{MAX_RECIPIENTS} recipients")
    for index, recipient in enumerate(recipients):
        if not isinstance(recipient, dict):
            raise MintError(f"recipient {index} must be a JSON object")
        if not isinstance(recipient.get("address"), str):
            raise MintError(f"recipient {index} address is malformed")
        gift = recipient.get("gift_sats")
        if isinstance(gift, bool) or not isinstance(gift, int) or gift <= 0:
            raise MintError(f"recipient {index} gift_sats must be a positive integer")
        consent = recipient.get("consent")
        mode = consent.get("mode") if isinstance(consent, dict) else None
        if not isinstance(mode, str) or mode not in {"self", "reference"}:
            raise MintError(f"recipient {index} consent is malformed")
    if not isinstance(chain, str) or chain not in {"main", "regtest"}:
        raise MintError("prepare chain must be main or regtest")
    if not isinstance(fee_rate, Decimal) or not isinstance(max_fee_rate, Decimal):
        raise MintError("fee rates must be Decimal sat/vB values")
    if (
        not fee_rate.is_finite()
        or not max_fee_rate.is_finite()
        or fee_rate <= 0
        or max_fee_rate <= 0
        or fee_rate > max_fee_rate
    ):
        raise MintError("requested fee rate exceeds the finite positive fee-rate cap")
    if (
        isinstance(max_carriers, bool)
        or not isinstance(max_carriers, int)
        or not 1 <= max_carriers <= MAX_STANDARD_CARRIERS
    ):
        raise MintError(f"max_carriers must be in 1..{MAX_STANDARD_CARRIERS}")
    for name, value in caps.items():
        if isinstance(value, bool) or not isinstance(value, int) or value <= 0:
            raise MintError(f"{name} must be a positive integer")
    count = carrier_count(len(content))
    if count > max_carriers:
        raise MintError(
            f"artifact needs {count} carriers, exceeding the approved maximum {max_carriers}"
        )
    return count


def preview_preparation(
    rpc: RPC,
    *,
    content: bytes,
    artifact_name: str,
    mime: str,
    recipients: Sequence[dict[str, Any]],
    chain: str,
    fee_rate: Decimal,
    max_fee_rate: Decimal,
    max_carriers: int,
    max_reveal_fee_sats: int,
    max_total_fee_sats: int,
    max_total_spend_sats: int,
    consent_ack: str | None,
    large_ack: str | None = None,
) -> dict[str, Any]:
    """Read-only validation and reveal-cost preview for ``prepare``."""
    rpc = ReadOnlyRPC(rpc)
    count = _validate_prepare_parameters(
        content=content,
        artifact_name=artifact_name,
        mime=mime,
        recipients=recipients,
        chain=chain,
        fee_rate=fee_rate,
        max_fee_rate=max_fee_rate,
        max_carriers=max_carriers,
        caps={
            "max_reveal_fee_sats": max_reveal_fee_sats,
            "max_total_fee_sats": max_total_fee_sats,
            "max_total_spend_sats": max_total_spend_sats,
        },
    )
    if count > DEFAULT_MAX_CARRIERS and large_ack != LARGE_ACK:
        raise MintError(
            f"178..221 carriers require the acknowledgement {LARGE_ACK!r}"
        )
    snapshot = inspect_node(
        rpc, chain, require_headroom=True, require_wallet=False
    )
    _, _, scripts = _new_carrier_key_and_scripts(content)
    manifest = build_manifest(content, mime)
    carrier_script = p2wsh_scriptpubkey(scripts[0])
    carrier_dust = _dust_threshold_sats(rpc, carrier_script)
    dummy_inputs = [TxInput(b"\x00" * 32, index) for index in range(count)]
    previews: list[dict[str, Any]] = []
    has_external = False
    reveal_fee_total = 0
    gift_total = 0
    for index, recipient in enumerate(recipients):
        mode = recipient["consent"]["mode"]
        recipient_script, is_mine = validate_p2tr_address(
            rpc, recipient["address"], check_wallet=(mode == "self")
        )
        if mode == "self" and not is_mine:
            raise MintError("a self recipient is not owned by the funding wallet")
        if mode == "reference":
            has_external = True
        pointer_dust = _dust_threshold_sats(rpc, recipient_script)
        if recipient["gift_sats"] < pointer_dust:
            raise MintError(
                f"gift to {recipient['address']} is below current dust threshold {pointer_dust}"
            )
        reveal_outputs = [
            TxOutput(recipient["gift_sats"], recipient_script),
            TxOutput(0, op_return_script(manifest)),
        ]
        reveal_budget = tx_with_placeholder_witnesses(
            dummy_inputs, reveal_outputs, scripts
        )
        reveal_fee = fee_for_vsize(fee_rate, reveal_budget.vsize)
        if reveal_fee > max_reveal_fee_sats:
            raise MintError(f"recipient {index} reveal fee {reveal_fee} exceeds its cap")
        carrier_total = recipient["gift_sats"] + reveal_fee
        _distribute_sats(carrier_total, count, carrier_dust)
        refund_budget = tx_with_placeholder_witnesses(
            dummy_inputs, [TxOutput(1, recipient_script)], scripts
        )
        refund_fee = fee_for_vsize(fee_rate, refund_budget.vsize)
        if carrier_total - refund_fee < pointer_dust:
            raise MintError("emergency refund output would be dust")
        previews.append(
            {
                "entry": index,
                "address": recipient["address"],
                "gift_sats": recipient["gift_sats"],
                "carriers": count,
                "reveal_vsize_upper_bound": reveal_budget.vsize,
                "reveal_fee_sats": reveal_fee,
                "refund_vsize_upper_bound": refund_budget.vsize,
                "refund_fee_sats": refund_fee,
                "carrier_dust_sats_each": carrier_dust,
            }
        )
        gift_total += recipient["gift_sats"]
        reveal_fee_total += reveal_fee
    if has_external and consent_ack != CONSENT_ACK:
        raise MintError(
            f"external recipients require --acknowledge-recipient-consent {CONSENT_ACK!r}"
        )
    if reveal_fee_total > max_total_fee_sats:
        raise MintError("aggregate reveal fees alone exceed the total fee cap")
    if gift_total + reveal_fee_total > max_total_spend_sats:
        raise MintError("aggregate gifts and reveal fees alone exceed the spend cap")
    return {
        "status": "validated-read-only",
        "artifact": {
            "name": artifact_name,
            "mime": mime,
            "length": len(content),
            "blake2b256": hashlib.blake2b(content, digest_size=32).hexdigest(),
            "carrier_count": count,
        },
        "chain_snapshot": snapshot,
        "entries": previews,
        "known_minimums": {
            "gift_sats": gift_total,
            "reveal_fee_sats": reveal_fee_total,
            "normal_path_spend_before_funding_fees_sats": gift_total + reveal_fee_total,
        },
        "funding_fee_sats": "unknown-until---execute",
        "mutations": [],
        "next": "review this preview, then repeat with --execute to create a signed plan",
    }


def prepare_plan(
    rpc: RPC,
    *,
    content: bytes,
    artifact_name: str,
    mime: str,
    recipients: Sequence[dict[str, Any]],
    chain: str,
    fee_rate: Decimal,
    max_fee_rate: Decimal,
    max_carriers: int,
    max_funding_fee_sats: int,
    max_reveal_fee_sats: int,
    max_total_fee_sats: int,
    max_total_spend_sats: int,
    consent_ack: str | None,
    large_ack: str | None = None,
    reservation_id: str | None = None,
    wallet_name: str | None = None,
    on_inputs_selected: Callable[
        [int, Sequence[dict[str, Any]]], None
    ] | None = None,
    on_locks_persisted: Callable[
        [int, Sequence[dict[str, Any]]], None
    ] | None = None,
) -> dict[str, Any]:
    """Prepare complete signed pairs and refunds without broadcasting anything."""
    count = _validate_prepare_parameters(
        content=content,
        artifact_name=artifact_name,
        mime=mime,
        recipients=recipients,
        chain=chain,
        fee_rate=fee_rate,
        max_fee_rate=max_fee_rate,
        max_carriers=max_carriers,
        caps={
            "max_funding_fee_sats": max_funding_fee_sats,
            "max_reveal_fee_sats": max_reveal_fee_sats,
            "max_total_fee_sats": max_total_fee_sats,
            "max_total_spend_sats": max_total_spend_sats,
        },
    )
    if count > DEFAULT_MAX_CARRIERS and large_ack != LARGE_ACK:
        raise MintError(
            f"178..221 carriers require the acknowledgement {LARGE_ACK!r}"
        )
    if chain == "main" and (
        on_inputs_selected is None or on_locks_persisted is None
    ):
        raise MintError("mainnet preparation requires a durable execution journal")
    snapshot = inspect_node(rpc, chain, require_headroom=True)
    wallet_info = _require_dict(rpc.call("getwalletinfo"), "getwalletinfo result")
    actual_wallet_name = wallet_info.get("walletname")
    if not isinstance(actual_wallet_name, str):
        raise MintError("funding wallet did not report its exact wallet name")
    if wallet_name is not None and wallet_name != actual_wallet_name:
        raise MintError("funding wallet identity changed before preparation")
    wallet_name = actual_wallet_name
    reservation_id = reservation_id or secrets.token_hex(16)
    _decode_hex_field(reservation_id, "reservation id", length=16)
    validated: list[tuple[dict[str, Any], bytes]] = []
    has_external = False
    pointer_dust: int | None = None
    for recipient in recipients:
        mode = recipient["consent"]["mode"]
        script, is_mine = validate_p2tr_address(
            rpc, recipient["address"], check_wallet=(mode == "self")
        )
        if pointer_dust is None:
            pointer_dust = _dust_threshold_sats(rpc, script)
        if recipient["gift_sats"] < pointer_dust:
            raise MintError(
                f"gift to {recipient['address']} is below current dust threshold {pointer_dust}"
            )
        if mode == "self" and not is_mine:
            raise MintError("a self recipient is not owned by the funding wallet")
        if mode == "reference":
            has_external = True
        validated.append((dict(recipient), script))
    if has_external and consent_ack != CONSENT_ACK:
        raise MintError(
            f"external recipients require --acknowledge-recipient-consent {CONSENT_ACK!r}"
        )
    assert pointer_dust is not None

    manifest = build_manifest(content, mime)
    artifact_digest = hashlib.blake2b(content, digest_size=32).hexdigest()
    maxfee_rpc = fee_rate_limit_btc_kvb(max_fee_rate)
    reserved_inputs: list[dict[str, Any]] = []
    entries: list[dict[str, Any]] = []
    try:
        for entry_index, (recipient, recipient_script) in enumerate(validated):
            refund_address, refund_script = _new_refund_address(rpc)
            secret, pubkey, scripts = _new_carrier_key_and_scripts(content)
            if len(scripts) != count:
                raise AssertionError("carrier count changed while preparing")

            dummy_inputs = [TxInput(b"\x00" * 32, index) for index in range(count)]
            reveal_outputs = [
                TxOutput(recipient["gift_sats"], recipient_script),
                TxOutput(0, op_return_script(manifest)),
            ]
            reveal_budget = tx_with_placeholder_witnesses(
                dummy_inputs, reveal_outputs, scripts
            )
            reveal_fee = fee_for_vsize(fee_rate, reveal_budget.vsize)
            if reveal_fee > max_reveal_fee_sats:
                raise MintError(
                    f"recipient {entry_index} reveal fee {reveal_fee} exceeds its cap"
                )
            carrier_total = recipient["gift_sats"] + reveal_fee
            carrier_dust = _dust_threshold_sats(rpc, p2wsh_scriptpubkey(scripts[0]))
            carrier_values = _distribute_sats(carrier_total, count, carrier_dust)

            refund_budget = tx_with_placeholder_witnesses(
                dummy_inputs, [TxOutput(1, refund_script)], scripts
            )
            refund_fee = fee_for_vsize(fee_rate, refund_budget.vsize)
            refund_value = carrier_total - refund_fee
            if refund_value < pointer_dust:
                raise MintError("emergency refund output would be dust")

            addresses = [p2wsh_address(script, chain) for script in scripts]
            # Cross-check our Bech32 implementation against Knots before asking
            # the wallet to fund any address.
            first_decoded = _require_dict(
                rpc.call("decodescript", scripts[0].hex()), "decodescript result"
            )
            segwit = _require_dict(first_decoded.get("segwit"), "decodescript segwit result")
            if (
                segwit.get("address") != addresses[0]
                or segwit.get("hex") != p2wsh_scriptpubkey(scripts[0]).hex()
            ):
                raise MintError("local P2WSH address encoding disagrees with Knots")
            funding_outputs = [
                {address: sats_to_btc(value)}
                for address, value in zip(addresses, carrier_values, strict=True)
            ]
            funding_outputs.append({"data": manifest.hex()})
            funding_hex, funding_fee, selected_inputs, change = _wallet_fund_and_sign(
                rpc,
                funding_outputs,
                fee_rate,
                before_persistent_lock=(
                    None
                    if on_inputs_selected is None
                    else lambda inputs, entry_index=entry_index: on_inputs_selected(
                        entry_index, inputs
                    )
                ),
                after_persistent_lock=(
                    None
                    if on_locks_persisted is None
                    else lambda inputs, entry_index=entry_index: on_locks_persisted(
                        entry_index, inputs
                    )
                ),
            )
            reserved_inputs.extend(selected_inputs)
            if funding_fee > max_funding_fee_sats:
                raise MintError(
                    f"recipient {entry_index} funding fee {funding_fee} exceeds its cap"
                )
            funding = parse_transaction(funding_hex)
            carrier_vouts = _assert_funding_shape(
                funding, scripts, carrier_values, manifest, change
            )
            spent_outputs = [funding.outputs[vout] for vout in carrier_vouts]

            unsigned_reveal = _build_unsigned_spend(
                funding.txid, carrier_vouts, reveal_outputs
            )
            reveal = sign_carrier_transaction(
                unsigned_reveal, spent_outputs, scripts, secret
            )
            refund_outputs = [TxOutput(refund_value, refund_script)]
            unsigned_refund = _build_unsigned_spend(
                funding.txid, carrier_vouts, refund_outputs
            )
            refund = sign_carrier_transaction(
                unsigned_refund, spent_outputs, scripts, secret
            )
            # Drop the only reference as soon as both alternatives exist. Python
            # cannot promise zeroization, but the scalar is never serialized.
            secret = 0

            _assert_carrier_spend(
                reveal,
                funding,
                carrier_vouts,
                scripts,
                reveal_outputs,
                content,
                manifest,
            )
            _assert_carrier_spend(
                refund,
                funding,
                carrier_vouts,
                scripts,
                refund_outputs,
                content,
                None,
            )
            actual_reveal_fee = sum(item.value_sats for item in spent_outputs) - sum(
                item.value_sats for item in reveal.outputs
            )
            actual_refund_fee = sum(item.value_sats for item in spent_outputs) - sum(
                item.value_sats for item in refund.outputs
            )
            if actual_reveal_fee != reveal_fee or actual_refund_fee != refund_fee:
                raise AssertionError("carrier spend fee accounting changed")
            if reveal.vsize > reveal_budget.vsize or refund.vsize > refund_budget.vsize:
                raise MintError("actual ECDSA signatures exceeded the 73-byte budget")
            if counterparty_collision(funding.inputs[0].prev_txid, manifest):
                raise MintError("funding manifest collided with Knots' Counterparty filter")
            if reveal.inputs[0].prev_txid != funding.txid:
                raise MintError("reveal first input does not spend the funding transaction")
            if counterparty_collision(reveal.inputs[0].prev_txid, manifest):
                raise MintError("reveal manifest collided with Knots' Counterparty filter")

            reveal_hex = reveal.serialize().hex()
            refund_hex = refund.serialize().hex()
            reveal_preflight = _assert_preflight(
                rpc,
                [funding_hex, reveal_hex],
                [funding_fee, reveal_fee],
                max_fee_rate,
                f"recipient {entry_index} reveal",
            )
            refund_preflight = _assert_preflight(
                rpc,
                [funding_hex, refund_hex],
                [funding_fee, refund_fee],
                max_fee_rate,
                f"recipient {entry_index} refund",
            )
            entries.append(
                {
                    "index": entry_index,
                    "recipient": recipient,
                    "recipient_script_pubkey": recipient_script.hex(),
                    "carrier_pubkey": pubkey.hex(),
                    "carrier_count": count,
                    "carrier_vouts": carrier_vouts,
                    "carrier_values_sats": carrier_values,
                    "manifest_hex": manifest.hex(),
                    "funding": {
                        "hex": funding_hex,
                        "txid": funding.txid,
                        "wtxid": funding.wtxid,
                        "fee_sats": funding_fee,
                        "weight": funding.weight,
                        "vsize": funding.vsize,
                        "locked_wallet_inputs": selected_inputs,
                        "change": change,
                    },
                    "reveal": {
                        "hex": reveal_hex,
                        "txid": reveal.txid,
                        "wtxid": reveal.wtxid,
                        "fee_sats": reveal_fee,
                        "weight": reveal.weight,
                        "vsize": reveal.vsize,
                        "pointer_vout": 0,
                        "preflight": reveal_preflight,
                    },
                    "refund": {
                        "hex": refund_hex,
                        "txid": refund.txid,
                        "wtxid": refund.wtxid,
                        "fee_sats": refund_fee,
                        "weight": refund.weight,
                        "vsize": refund.vsize,
                        "address": refund_address,
                        "script_pubkey": refund_script.hex(),
                        "value_sats": refund_value,
                        "preflight": refund_preflight,
                    },
                }
            )
            normal_fee_total = sum(
                item["funding"]["fee_sats"] + item["reveal"]["fee_sats"]
                for item in entries
            )
            normal_spend_total = normal_fee_total + sum(
                item["recipient"]["gift_sats"] for item in entries
            )
            if normal_fee_total > max_total_fee_sats:
                raise MintError("aggregate funding and reveal fees exceed the cap")
            if normal_spend_total > max_total_spend_sats:
                raise MintError("aggregate gifts and fees exceed the spend cap")

        total_fee = sum(
            item["funding"]["fee_sats"] + item["reveal"]["fee_sats"]
            for item in entries
        )
        total_gifts = sum(item["recipient"]["gift_sats"] for item in entries)
        plan = {
            "format": FORMAT,
            "schema_version": SCHEMA_VERSION,
            "plan_id": secrets.token_hex(16),
            "created_at": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
            "state": "PREPARED_NOT_BROADCAST",
            "reservation": {
                "id": reservation_id,
                "wallet_name": wallet_name,
                "journal_format": JOURNAL_FORMAT,
            },
            "chain_snapshot": snapshot,
            "artifact": {
                "name": artifact_name,
                "mime": mime,
                "length": len(content),
                "blake2b256": artifact_digest,
                "carrier_count": count,
            },
            "policy": {
                "consent": "recorded-not-cryptographically-verified",
                "fee_rate_sat_vb": format(fee_rate, "f"),
                "max_fee_rate_sat_vb": format(max_fee_rate, "f"),
                "max_carriers": max_carriers,
                "max_funding_fee_sats_each": max_funding_fee_sats,
                "max_reveal_fee_sats_each": max_reveal_fee_sats,
                "max_total_fee_sats": max_total_fee_sats,
                "max_total_spend_sats": max_total_spend_sats,
                "maxfeerate_rpc_btc_kvb": format(maxfee_rpc, "f"),
                "requires_funding_confirmations": 1,
            },
            "totals": {
                "recipients": len(entries),
                "gift_sats": total_gifts,
                "normal_path_fee_sats": total_fee,
                "normal_path_spend_sats": total_gifts + total_fee,
                "temporarily_locked_carrier_sats": sum(
                    sum(item["carrier_values_sats"]) for item in entries
                ),
            },
            "entries": entries,
        }
        sealed = seal_plan(plan)
        verify_plan(sealed)
        return sealed
    except BaseException as exc:
        cleanup_candidates = list(reserved_inputs)
        primary = exc
        if isinstance(exc, LockCleanupError):
            cleanup_candidates.extend(exc.candidates)
            primary = exc.primary
        _cleanup_reserved_after_failure(rpc, cleanup_candidates, primary)
        if primary is not exc:
            raise primary
        raise


def _entry_indices(plan: dict[str, Any], selection: str) -> list[int]:
    entries = plan.get("entries")
    if not isinstance(entries, list) or not entries:
        raise MintError("plan has no entries")
    if not isinstance(selection, str):
        raise MintError("--entry must be a zero-based integer or all")
    if selection == "all":
        return list(range(len(entries)))
    try:
        index = int(selection)
    except ValueError as exc:
        raise MintError("--entry must be a zero-based integer or all") from exc
    if not 0 <= index < len(entries):
        raise MintError("--entry is outside the plan")
    return [index]


def _mempool_contains(
    rpc: RPC, txid: str, expected_wtxid: str | None = None
) -> bool:
    try:
        result = rpc.call("getmempoolentry", txid)
    except KnotsRPCError as exc:
        if exc.code == -5:
            return False
        raise
    if not isinstance(result, dict):
        raise MintError("getmempoolentry returned a malformed result")
    if expected_wtxid is not None and result.get("wtxid") != expected_wtxid:
        raise MintError("mempool entry witness id differs from the saved transaction")
    return True


def _checked_txout(
    rpc: RPC,
    txid: str,
    vout: int,
    expected: TxOutput,
    *,
    include_mempool: bool = True,
) -> dict[str, Any] | None:
    result = rpc.call("gettxout", txid, vout, include_mempool)
    if result is None:
        return None
    utxo = _require_dict(result, "gettxout result")
    if btc_to_sats(utxo.get("value")) != expected.value_sats:
        raise MintError("node UTXO value differs from the exact saved transaction")
    script = _require_dict(utxo.get("scriptPubKey"), "gettxout scriptPubKey")
    if script.get("hex") != expected.script_pubkey.hex():
        raise MintError("node UTXO script differs from the exact saved transaction")
    confirmations = utxo.get("confirmations")
    if isinstance(confirmations, bool) or not isinstance(confirmations, int) or confirmations < 0:
        raise MintError("gettxout returned invalid confirmations")
    return utxo


def _raw_transaction_known(
    rpc: RPC, transaction_record: dict[str, Any]
) -> bool:
    """Best-effort node-wide lookup; absence is inconclusive without txindex."""
    try:
        raw = rpc.call("getrawtransaction", transaction_record["txid"], False)
    except KnotsRPCError as exc:
        if exc.code == -5:
            return False
        raise
    if not isinstance(raw, str):
        return False
    parsed = parse_transaction(raw)
    if (
        parsed.txid != transaction_record["txid"]
        or parsed.wtxid != transaction_record["wtxid"]
    ):
        raise MintError("node returned different bytes for a saved transaction id")
    return True


def _saved_stage_observation(
    rpc: RPC,
    entry: dict[str, Any],
    stage: str,
) -> dict[str, Any]:
    record = entry[stage]
    transaction = parse_transaction(record["hex"])
    output_vout = record.get("pointer_vout", 0) if stage == "reveal" else 0
    output = transaction.outputs[output_vout]
    utxo = _checked_txout(rpc, record["txid"], output_vout, output)
    if utxo is not None:
        confirmations = utxo["confirmations"]
        return {
            "known": True,
            "status": "unconfirmed" if confirmations == 0 else "confirmed",
            "confirmations": confirmations,
            "output_unspent": True,
        }
    confirmed_utxo = _checked_txout(
        rpc,
        record["txid"],
        output_vout,
        output,
        include_mempool=False,
    )
    if confirmed_utxo is not None:
        return {
            "known": True,
            "status": "confirmed-output-spent-by-mempool",
            "confirmations": confirmed_utxo["confirmations"],
            "output_unspent": False,
        }
    if _mempool_contains(rpc, record["txid"], record["wtxid"]):
        return {
            "known": True,
            "status": "in-mempool-output-spent",
            "confirmations": 0,
            "output_unspent": False,
        }
    if _raw_transaction_known(rpc, record):
        return {
            "known": True,
            "status": "known-output-spent",
            "confirmations": None,
            "output_unspent": False,
        }
    return {
        "known": False,
        "status": "unknown",
        "confirmations": None,
        "output_unspent": False,
    }


def _carrier_snapshot(rpc: RPC, entry: dict[str, Any]) -> dict[str, Any]:
    funding = parse_transaction(entry["funding"]["hex"])
    present: list[dict[str, Any]] = []
    pending_spend: list[int] = []
    missing = 0
    for vout in entry["carrier_vouts"]:
        utxo = _checked_txout(rpc, funding.txid, vout, funding.outputs[vout])
        if utxo is None:
            confirmed = _checked_txout(
                rpc,
                funding.txid,
                vout,
                funding.outputs[vout],
                include_mempool=False,
            )
            if confirmed is None:
                missing += 1
            else:
                pending_spend.append(vout)
        else:
            present.append(utxo)
    if pending_spend:
        probes = [{"txid": funding.txid, "vout": vout} for vout in pending_spend]
        spending = rpc.call("gettxspendingprevout", probes)
        if not isinstance(spending, list) or len(spending) != len(probes):
            raise MintError("gettxspendingprevout returned a malformed result")
        spenders = {
            item.get("spendingtxid")
            for item in spending
            if isinstance(item, dict) and isinstance(item.get("spendingtxid"), str)
        }
        if len(spenders) == 1 and len(pending_spend) == len(entry["carrier_vouts"]):
            spender = spenders.pop()
            if spender == entry["reveal"]["txid"]:
                state = "pending-reveal"
            elif spender == entry["refund"]["txid"]:
                state = "pending-refund"
            else:
                state = "pending-foreign-spend"
        else:
            state = "pending-mixed-spend"
        return {
            "state": state,
            "confirmations": None,
            "present": len(present),
            "missing": missing,
            "pending_spend": len(pending_spend),
        }
    if present and missing:
        return {
            "state": "partially-spent",
            "confirmations": None,
            "present": len(present),
            "missing": missing,
        }
    if present:
        confirmations = {item["confirmations"] for item in present}
        if len(confirmations) != 1:
            raise MintError("carrier UTXOs report inconsistent confirmations")
        return {
            "state": "unspent",
            "confirmations": confirmations.pop(),
            "present": len(present),
            "missing": 0,
        }
    return {
        "state": "absent-or-spent",
        "confirmations": None,
        "present": 0,
        "missing": missing,
    }


def _funding_observation(rpc: RPC, entry: dict[str, Any]) -> dict[str, Any]:
    txid = entry["funding"]["txid"]
    if _mempool_contains(rpc, txid, entry["funding"]["wtxid"]):
        return {"known": True, "status": "in-mempool", "confirmations": 0}
    carriers = _carrier_snapshot(rpc, entry)
    if carriers["state"] == "unspent":
        return {
            "known": True,
            "status": "unconfirmed" if carriers["confirmations"] == 0 else "confirmed",
            "confirmations": carriers["confirmations"],
        }
    if carriers["state"] == "partially-spent":
        return {"known": True, "status": "partially-spent", "confirmations": None}
    if carriers["state"].startswith("pending-"):
        return {"known": True, "status": carriers["state"], "confirmations": None}
    if _raw_transaction_known(rpc, entry["funding"]):
        return {"known": True, "status": "known-carriers-spent", "confirmations": None}
    for stage in ("reveal", "refund"):
        child = _saved_stage_observation(rpc, entry, stage)
        if child["known"]:
            return {
                "known": True,
                "status": f"spent-by-{stage}",
                "confirmations": None,
            }
    return {"known": False, "status": "unknown", "confirmations": None}


def _assert_saved_entry_invariants(entry: dict[str, Any], content: bytes | None = None) -> None:
    funding = parse_transaction(entry["funding"]["hex"])
    reveal = parse_transaction(entry["reveal"]["hex"])
    refund = parse_transaction(entry["refund"]["hex"])
    manifest = _decode_hex_field(entry.get("manifest_hex"), "saved manifest")
    if counterparty_collision(funding.inputs[0].prev_txid, manifest):
        raise MintError("saved funding now matches the Counterparty predicate")
    if counterparty_collision(reveal.inputs[0].prev_txid, manifest):
        raise MintError("saved reveal now matches the Counterparty predicate")
    carrier_vouts = entry["carrier_vouts"]
    if not isinstance(carrier_vouts, list) or len(carrier_vouts) != entry["carrier_count"]:
        raise MintError("saved carrier vout list is malformed")
    if len(reveal.inputs) != len(carrier_vouts):
        raise MintError("saved reveal input count differs from the carrier list")
    if any(
        isinstance(vout, bool)
        or not isinstance(vout, int)
        or not 0 <= vout < len(funding.outputs)
        for vout in carrier_vouts
    ):
        raise MintError("saved carrier vout is outside the funding transaction")
    scripts: list[bytes] = []
    for index, txin in enumerate(reveal.inputs):
        if len(txin.witness) != 2:
            raise MintError("saved reveal witness shape is malformed")
        validate_signature_item(txin.witness[0])
        scripts.append(txin.witness[1])
        if txin.prev_txid != funding.txid or txin.prev_vout != carrier_vouts[index]:
            raise MintError("saved reveal does not spend canonical carrier outpoints")
        if p2wsh_scriptpubkey(txin.witness[1]) != funding.outputs[carrier_vouts[index]].script_pubkey:
            raise MintError("saved reveal witnessScript does not match funding")
    if _assert_funding_shape(
        funding,
        scripts,
        entry["carrier_values_sats"],
        manifest,
        entry["funding"].get("change"),
    ) != carrier_vouts:
        raise MintError("saved funding carrier order changed")
    locked_inputs = entry["funding"].get("locked_wallet_inputs")
    if not isinstance(locked_inputs, list) or any(
        not isinstance(item, dict) for item in locked_inputs
    ):
        raise MintError("saved funding wallet inputs are malformed")
    if locked_inputs != [
        {"txid": txin.prev_txid, "vout": txin.prev_vout} for txin in funding.inputs
    ]:
        raise MintError("saved funding wallet inputs differ from the signed transaction")
    if not _funding_signature_types_are_unified(funding):
        raise MintError("saved funding does not use explicit unified signatures")
    pubkey = _decode_hex_field(
        entry.get("carrier_pubkey"), "saved carrier public key", length=33
    )
    spent_outputs = [funding.outputs[vout] for vout in carrier_vouts]
    for candidate_name, candidate in (("reveal", reveal), ("refund", refund)):
        if len(candidate.inputs) != len(scripts):
            raise MintError(f"saved {candidate_name} input count changed")
        for index, (txin, vout, script) in enumerate(
            zip(candidate.inputs, carrier_vouts, scripts, strict=True)
        ):
            if txin.prev_txid != funding.txid or txin.prev_vout != vout:
                raise MintError(f"saved {candidate_name} carrier order changed")
            if txin.script_sig or txin.sequence != 0xFFFFFFFD:
                raise MintError(f"saved {candidate_name} input framing changed")
            if len(txin.witness) != 2 or txin.witness[1] != script:
                raise MintError(f"saved {candidate_name} witness changed")
            validate_signature_item(txin.witness[0])
            digest = unified_witness_v0_sighash(
                candidate, index, script, spent_outputs
            )
            if not verify_ecdsa(pubkey, digest, txin.witness[0][:-1]):
                raise MintError(f"saved {candidate_name} signature does not verify")
    recipient_script = _decode_hex_field(
        entry.get("recipient_script_pubkey"),
        "saved recipient scriptPubKey",
        length=34,
    )
    if recipient_script[:2] != b"\x51\x20":
        raise MintError("saved recipient scriptPubKey is not exact P2TR")
    if reveal.outputs != [
        TxOutput(
            entry["recipient"]["gift_sats"],
            recipient_script,
        ),
        TxOutput(0, op_return_script(manifest)),
    ]:
        raise MintError("saved reveal pointer or manifest output changed")
    recovered = decode_committed_witnesses(
        manifest,
        manifest,
        [item.witness for item in reveal.inputs],
        expected_pubkey=pubkey,
    )
    if content is not None and recovered != content:
        raise MintError("saved reveal does not decode to the supplied artifact")
    refund_script = _decode_hex_field(
        entry["refund"].get("script_pubkey"),
        "saved refund scriptPubKey",
        length=34,
    )
    if refund_script[:2] != b"\x51\x20":
        raise MintError("saved refund scriptPubKey is not exact P2TR")
    expected_refund = TxOutput(
        entry["refund"]["value_sats"],
        refund_script,
    )
    if refund.outputs != [expected_refund]:
        raise MintError("saved refund output changed")
    for name, transaction in (
        ("funding", funding),
        ("reveal", reveal),
        ("refund", refund),
    ):
        if (
            transaction.weight != entry[name].get("weight")
            or transaction.vsize != entry[name].get("vsize")
        ):
            raise MintError(f"saved {name} transaction size changed")
    funding_fee = entry["funding"]["fee_sats"]
    if isinstance(funding_fee, bool) or not isinstance(funding_fee, int) or funding_fee < 0:
        raise MintError("saved funding fee is malformed")
    reveal_fee = sum(funding.outputs[v].value_sats for v in carrier_vouts) - sum(
        item.value_sats for item in reveal.outputs
    )
    refund_fee = sum(funding.outputs[v].value_sats for v in carrier_vouts) - sum(
        item.value_sats for item in refund.outputs
    )
    if (
        reveal_fee != entry["reveal"]["fee_sats"]
        or refund_fee != entry["refund"]["fee_sats"]
        or funding_fee < 0
    ):
        raise MintError("saved transaction fee accounting changed")


def _assert_saved_consent_current(entry: dict[str, Any]) -> None:
    consent = _require_dict(entry["recipient"]["consent"], "saved consent")
    if consent.get("mode") == "reference":
        expiry = _parse_utc_timestamp(consent.get("expires_at"), "saved consent expiry")
        if expiry <= datetime.now(timezone.utc):
            raise MintError("saved recipient consent has expired")


def _assert_chain_matches_plan(
    rpc: RPC,
    plan: dict[str, Any],
    *,
    minting: bool,
    require_headroom: bool = False,
    require_fresh: bool = False,
) -> dict[str, Any]:
    saved = _require_dict(plan.get("chain_snapshot"), "plan chain snapshot")
    if minting:
        current = inspect_node(
            rpc,
            saved["chain"],
            require_headroom=require_headroom,
            require_wallet=False,
        )
    else:
        current = inspect_chain_identity(
            rpc, saved["chain"], require_fresh=require_fresh
        )
    if current["genesis"] != saved.get("genesis"):
        raise MintError("connected network does not match the saved plan")
    return current


def _check_carriers_unspent(
    rpc: RPC, entry: dict[str, Any], *, min_confirmations: int
) -> int:
    snapshot = _carrier_snapshot(rpc, entry)
    if snapshot["state"] != "unspent":
        raise MintError(
            "one or more carriers are spent or unknown; determine whether reveal or refund won"
        )
    confirmations = snapshot["confirmations"]
    if confirmations < min_confirmations:
        raise MintError(
            f"funding has {confirmations} confirmations; {min_confirmations} required"
        )
    return confirmations


def _single_preflight(
    rpc: RPC,
    raw: str,
    fee_sats: int,
    max_fee_rate: Decimal,
    description: str,
) -> None:
    _assert_preflight(rpc, [raw], [fee_sats], max_fee_rate, description)


def _broadcast_gateway(
    rpc: RPC,
    *,
    raw: str,
    expected_txid: str,
    max_fee_rate: Decimal,
) -> str:
    """The sole state-changing transaction-broadcast call in this module."""
    returned = rpc.call(
        "sendrawtransaction",
        raw,
        fee_rate_limit_btc_kvb(max_fee_rate),
        0,
        [],
    )
    if returned != expected_txid:
        raise MintError("sendrawtransaction returned an unexpected transaction id")
    return returned


def broadcast_plan_stage(
    rpc: RPC,
    plan: dict[str, Any],
    *,
    stage: str,
    selection: str,
    execute: bool = False,
    acknowledgement: str | None = None,
    approved_plan_checksum: str | None = None,
    refund_acknowledgement: str | None = None,
    min_confirmations: int = 1,
    journal: ExecutionJournal | None = None,
) -> list[dict[str, Any]]:
    """Preflight and broadcast an explicitly selected saved stage."""
    if not isinstance(execute, bool):
        raise MintError("execute must be an explicit boolean")
    if not execute:
        rpc = ReadOnlyRPC(rpc)
    verify_plan(plan)
    if not isinstance(stage, str) or stage not in {"funding", "reveal", "refund"}:
        raise MintError("stage must be funding, reveal, or refund")
    chain = plan["chain_snapshot"]["chain"]
    if execute and chain == "main" and acknowledgement != BROADCAST_ACK:
        raise MintError(f"mainnet broadcast requires acknowledgement {BROADCAST_ACK!r}")
    if execute and chain == "main":
        if (
            not isinstance(approved_plan_checksum, str)
            or len(approved_plan_checksum) != 64
            or approved_plan_checksum != approved_plan_checksum.lower()
            or any(
                char not in "0123456789abcdef" for char in approved_plan_checksum
            )
            or not hmac.compare_digest(
                approved_plan_checksum, plan["checksum_blake2b256"]
            )
        ):
            raise MintError(
                "mainnet broadcast requires --approve-plan-checksum matching the exact plan"
            )
    if execute and chain == "main" and selection == "all":
        raise MintError("mainnet broadcast requires one explicit --entry at a time")
    if journal is not None:
        journal.validate_for_plan(plan)
    if execute and chain == "main" and journal is None:
        raise MintError("mainnet execution requires the plan's bound execution journal")
    if execute and stage == "refund" and refund_acknowledgement != REFUND_ACK:
        raise MintError(f"refund broadcast requires acknowledgement {REFUND_ACK!r}")
    if (
        isinstance(min_confirmations, bool)
        or not isinstance(min_confirmations, int)
        or min_confirmations < 1
    ):
        raise MintError("min_confirmations must be at least one")
    indices = _entry_indices(plan, selection)
    # Known-state reconciliation only needs chain identity. This keeps an
    # idempotent retry informative after consent/RDTS expiry or a node upgrade;
    # strict minting gates are applied below before any new action.
    _assert_chain_matches_plan(rpc, plan, minting=False)
    max_fee_rate = parse_fee_rate(plan["policy"]["max_fee_rate_sat_vb"])
    results: list[dict[str, Any]] = []
    action_gate_checked = False
    for index in indices:
        entry = plan["entries"][index]
        _assert_saved_entry_invariants(entry)
        transaction = entry[stage]
        txid = transaction["txid"]
        if stage == "funding":
            observation = _funding_observation(rpc, entry)
            if observation["known"]:
                if execute and journal is not None:
                    journal.record_funding_irreversible(index, txid, observed=True)
                results.append(
                    {
                        "entry": index,
                        "stage": stage,
                        "txid": txid,
                        "status": "already-known",
                        "location": observation["status"],
                        "confirmations": observation["confirmations"],
                    }
                )
                continue
        else:
            observation = _saved_stage_observation(rpc, entry, stage)
            if observation["known"]:
                if execute and journal is not None:
                    journal.observe_spend(index, stage, txid)
                results.append(
                    {
                        "entry": index,
                        "stage": stage,
                        "txid": txid,
                        "status": "already-known",
                        "location": observation["status"],
                        "confirmations": observation["confirmations"],
                    }
                )
                continue
            competitor = "refund" if stage == "reveal" else "reveal"
            competing_observation = _saved_stage_observation(rpc, entry, competitor)
            if competing_observation["known"]:
                if execute and journal is not None:
                    journal.observe_spend(
                        index, competitor, entry[competitor]["txid"]
                    )
                raise MintError(
                    f"cannot broadcast {stage}: the saved {competitor} is already known"
                )

        if not action_gate_checked:
            _assert_chain_matches_plan(
                rpc,
                plan,
                minting=(stage != "refund"),
                require_headroom=(stage == "funding"),
                require_fresh=execute,
            )
            action_gate_checked = True
        if stage != "refund":
            _assert_saved_consent_current(entry)
            recipient_script, _ = validate_p2tr_address(
                rpc, entry["recipient"]["address"]
            )
            if recipient_script.hex() != entry["recipient_script_pubkey"]:
                raise MintError("recipient address no longer matches the saved script")

        if stage == "funding":
            _assert_preflight(
                rpc,
                [entry["funding"]["hex"], entry["reveal"]["hex"]],
                [entry["funding"]["fee_sats"], entry["reveal"]["fee_sats"]],
                max_fee_rate,
                f"entry {index} funding/reveal",
            )
            _assert_preflight(
                rpc,
                [entry["funding"]["hex"], entry["refund"]["hex"]],
                [entry["funding"]["fee_sats"], entry["refund"]["fee_sats"]],
                max_fee_rate,
                f"entry {index} funding/refund",
            )
        else:
            _check_carriers_unspent(
                rpc, entry, min_confirmations=min_confirmations
            )
            _single_preflight(
                rpc,
                transaction["hex"],
                transaction["fee_sats"],
                max_fee_rate,
                f"entry {index} {stage}",
            )
        if not execute:
            results.append(
                {
                    "entry": index,
                    "stage": stage,
                    "txid": txid,
                    "status": "preflight-ok-not-broadcast",
                }
            )
            continue
        if stage != "refund":
            # Consent can expire while hundreds of carrier UTXOs and the exact
            # package are being checked. Re-evaluate at the last possible
            # point before recording a send attempt.
            _assert_saved_consent_current(entry)
        if journal is not None:
            if stage == "funding":
                journal.record_funding_irreversible(index, txid)
            else:
                journal.select_spend(index, stage, txid)
        try:
            sent = _broadcast_gateway(
                rpc,
                raw=transaction["hex"],
                expected_txid=txid,
                max_fee_rate=max_fee_rate,
            )
        except MintError:
            # A timeout after successful submission must never produce a new
            # transaction. Reconcile by the precomputed txid only.
            if stage == "funding":
                reconciled = _funding_observation(rpc, entry)["known"]
            else:
                reconciled = _saved_stage_observation(rpc, entry, stage)["known"]
            if reconciled:
                sent = txid
            else:
                raise
        results.append({"entry": index, "stage": stage, "txid": sent, "status": "broadcast"})
    return results


def plan_status(rpc: RPC, plan: dict[str, Any]) -> dict[str, Any]:
    verify_plan(plan)
    _assert_chain_matches_plan(rpc, plan, minting=False)
    result: list[dict[str, Any]] = []
    for entry in plan["entries"]:
        funding = _funding_observation(rpc, entry)
        carriers = _carrier_snapshot(rpc, entry)
        reveal = _saved_stage_observation(rpc, entry, "reveal")
        refund = _saved_stage_observation(rpc, entry, "refund")
        if reveal["known"] and refund["known"]:
            winner = "invalid-both-alternatives-known"
        elif reveal["known"]:
            winner = "reveal"
        elif refund["known"]:
            winner = "refund"
        elif carriers["state"] == "unspent":
            winner = "neither-carriers-unspent"
        elif funding["known"]:
            winner = "unknown-carriers-spent"
        else:
            winner = "funding-not-observed"
        result.append(
            {
                "entry": entry["index"],
                "funding_txid": entry["funding"]["txid"],
                "funding": funding,
                "carriers": carriers,
                "reveal_txid": entry["reveal"]["txid"],
                "reveal": reveal,
                "refund_txid": entry["refund"]["txid"],
                "refund": refund,
                "winner": winner,
            }
        )
    return {
        "plan_id": plan["plan_id"],
        "plan_checksum": plan["checksum_blake2b256"],
        "chain": plan["chain_snapshot"]["chain"],
        "entries": result,
    }


def unlock_plan_inputs(
    rpc: RPC,
    plan: dict[str, Any],
    *,
    selection: str,
    journal: ExecutionJournal,
    execute: bool = False,
    acknowledgement: str | None = None,
) -> dict[str, Any]:
    """Release one entry only when its intact journal proves no tool send attempt."""
    if not isinstance(execute, bool):
        raise MintError("execute must be an explicit boolean")
    verify_plan(plan)
    journal.validate_for_plan(plan)
    if selection == "all":
        raise MintError("unlock requires one explicit entry at a time")
    indices = _entry_indices(plan, selection)
    if execute and acknowledgement != UNLOCK_ACK:
        raise MintError(f"unlock requires acknowledgement {UNLOCK_ACK!r}")
    if not execute:
        rpc = ReadOnlyRPC(rpc)
    _assert_chain_matches_plan(rpc, plan, minting=False, require_fresh=execute)
    wallet = _require_dict(rpc.call("getwalletinfo"), "getwalletinfo result")
    if wallet.get("scanning") not in (False, None):
        raise MintError("funding wallet is currently scanning")
    if wallet.get("walletname") != plan["reservation"]["wallet_name"]:
        raise MintError("loaded wallet does not match the plan reservation")
    # Wallet names are only local labels. Prove that this wallet also controls
    # each checksum-bound refund key before allowing any journal transition.
    for index in indices:
        refund = plan["entries"][index]["refund"]
        refund_script, _ = validate_p2tr_address(rpc, refund["address"])
        refund_info = _require_dict(
            rpc.call("getaddressinfo", refund["address"]),
            "refund getaddressinfo result",
        )
        if (
            refund_script.hex() != refund["script_pubkey"]
            or refund_info.get("ismine") is not True
            or refund_info.get("solvable") is not True
            or refund_info.get("iswatchonly") is True
        ):
            raise MintError(
                "loaded wallet does not control the plan's exact refund address"
            )
    unlocked: list[dict[str, Any]] = []
    would_unlock: list[dict[str, Any]] = []
    already_unlocked: list[dict[str, Any]] = []
    skipped: list[dict[str, Any]] = []
    for index in indices:
        entry = plan["entries"][index]
        journal_state = journal.unlock_state(index)
        if journal_state == "blocked":
            raise MintError(
                f"entry {index} cannot be auto-unlocked: its journal records an "
                "attempted/observed funding or carrier spend"
            )
        if journal_state == "unlocked":
            relocked = _locked_intersection(
                rpc, entry["funding"]["locked_wallet_inputs"]
            )
            if relocked:
                raise MintError(
                    f"entry {index} was already terminally unlocked but an outpoint is "
                    "locked again; its current ownership is unknown"
                )
            already_unlocked.extend(entry["funding"]["locked_wallet_inputs"])
            continue
        observation = _funding_observation(rpc, entry)
        inputs = entry["funding"]["locked_wallet_inputs"]
        if observation["known"]:
            if execute:
                journal.record_funding_irreversible(
                    index, entry["funding"]["txid"], observed=True
                )
            skipped.append(
                {
                    "entry": index,
                    "reason": observation["status"],
                    "inputs": inputs,
                }
            )
            continue
        currently_locked = _locked_intersection(rpc, inputs)
        if execute:
            journal.begin_unlock(index, inputs)
            unlocked.extend(_unlock_exact_wallet_inputs(rpc, currently_locked))
            remaining = _locked_intersection(rpc, inputs)
            if remaining:
                raise MintError("wallet retained one or more exact plan input locks")
            journal.finish_unlock(index, inputs)
        else:
            would_unlock.extend(currently_locked)
        locked_keys = {(item["txid"], item["vout"]) for item in currently_locked}
        already_unlocked.extend(
            item
            for item in inputs
            if (item["txid"], item["vout"]) not in locked_keys
        )
    return {
        "status": "unlocked" if execute else "dry-run-not-unlocked",
        "unlocked": unlocked,
        "would_unlock": would_unlock,
        "already_unlocked": already_unlocked,
        "skipped_known_funding": skipped,
        "entry": indices[0],
        "journal": str(journal.path),
    }


def _add_rpc_arguments(
    parser: argparse.ArgumentParser, *, wallet_required: bool = False
) -> None:
    parser.add_argument("--bitcoin-cli", default="bitcoin-cli")
    parser.add_argument(
        "--wallet",
        required=wallet_required,
        help="Knots wallet name (required only for prepare --execute and unlock)",
    )
    parser.add_argument("--datadir")
    parser.add_argument("--conf")
    parser.add_argument("--rpcconnect")
    parser.add_argument("--rpcport", type=int)
    parser.add_argument("--allow-remote-rpc", action="store_true")


def _rpc_from_args(args: argparse.Namespace) -> BitcoinCliRPC:
    return BitcoinCliRPC(
        args.bitcoin_cli,
        wallet=getattr(args, "wallet", None),
        datadir=args.datadir,
        conf=args.conf,
        rpcconnect=args.rpcconnect,
        rpcport=args.rpcport,
        allow_remote_rpc=args.allow_remote_rpc,
    )


def _positive_int(value: str) -> int:
    try:
        parsed = int(value)
    except ValueError as exc:
        raise argparse.ArgumentTypeError("must be an integer") from exc
    if parsed <= 0:
        raise argparse.ArgumentTypeError("must be greater than zero")
    return parsed


def build_argument_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Guarded BORDINALS prepare/broadcast tool for pinned Knots v29.4.1"
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    prepare = subparsers.add_parser(
        "prepare", help="sign and preflight a mode-0600 plan; never broadcast"
    )
    prepare.add_argument("artifact", type=Path)
    prepare.add_argument("--mime", required=True)
    prepare.add_argument("--recipients", required=True, type=Path)
    prepare.add_argument("--plan-out", type=Path)
    prepare.add_argument("--chain", choices=("main", "regtest"), default="main")
    prepare.add_argument("--fee-rate-sat-vb", required=True)
    prepare.add_argument("--max-fee-rate-sat-vb", default="10")
    prepare.add_argument("--max-carriers", type=_positive_int, default=DEFAULT_MAX_CARRIERS)
    prepare.add_argument("--max-funding-fee-sats", type=_positive_int, default=100_000)
    prepare.add_argument("--max-reveal-fee-sats", type=_positive_int, default=1_000_000)
    prepare.add_argument("--max-total-fee-sats", type=_positive_int, default=5_000_000)
    prepare.add_argument("--max-total-spend-sats", type=_positive_int, default=5_000_000)
    prepare.add_argument("--acknowledge-recipient-consent")
    prepare.add_argument("--acknowledge-mainnet")
    prepare.add_argument("--acknowledge-large-transaction")
    prepare.add_argument(
        "--execute",
        action="store_true",
        help="derive addresses, sign transactions, and persistently lock wallet inputs",
    )
    _add_rpc_arguments(prepare)

    broadcast = subparsers.add_parser(
        "broadcast", help="broadcast one exact saved stage after a fresh preflight"
    )
    broadcast.add_argument("plan", type=Path)
    broadcast.add_argument("--stage", choices=("funding", "reveal", "refund"), required=True)
    broadcast.add_argument("--entry", required=True, help="zero-based entry number or all")
    broadcast.add_argument("--min-confirmations", type=_positive_int, default=1)
    broadcast.add_argument("--acknowledge")
    broadcast.add_argument("--approve-plan-checksum")
    broadcast.add_argument("--acknowledge-refund")
    broadcast.add_argument(
        "--execute", action="store_true", help="submit the exact saved transaction"
    )
    _add_rpc_arguments(broadcast)

    status = subparsers.add_parser("status", help="read chain status for a saved plan")
    status.add_argument("plan", type=Path)
    _add_rpc_arguments(status)

    unlock = subparsers.add_parser(
        "unlock", help="unlock one entry only when its intact journal allows it"
    )
    unlock.add_argument("plan", type=Path)
    unlock.add_argument("--entry", required=True, help="one zero-based entry number")
    unlock.add_argument("--acknowledge")
    unlock.add_argument(
        "--execute", action="store_true", help="release the listed wallet locks"
    )
    _add_rpc_arguments(unlock, wallet_required=True)
    return parser


def _print_json(value: Any) -> None:
    print(json.dumps(value, indent=2, sort_keys=True))


def main(argv: Sequence[str] | None = None) -> int:
    parser = build_argument_parser()
    args = parser.parse_args(argv)
    try:
        rpc = _rpc_from_args(args)
        if args.command == "prepare":
            content = args.artifact.expanduser().read_bytes()
            digest = hashlib.blake2b(content, digest_size=32).hexdigest()
            recipients = load_consent_records(
                args.recipients,
                chain=args.chain,
                artifact_digest=digest,
            )
            fee_rate = parse_fee_rate(args.fee_rate_sat_vb)
            max_fee_rate = parse_fee_rate(args.max_fee_rate_sat_vb)
            if not args.execute:
                _print_json(
                    preview_preparation(
                        rpc,
                        content=content,
                        artifact_name=args.artifact.name,
                        mime=args.mime,
                        recipients=recipients,
                        chain=args.chain,
                        fee_rate=fee_rate,
                        max_fee_rate=max_fee_rate,
                        max_carriers=args.max_carriers,
                        max_reveal_fee_sats=args.max_reveal_fee_sats,
                        max_total_fee_sats=args.max_total_fee_sats,
                        max_total_spend_sats=args.max_total_spend_sats,
                        consent_ack=args.acknowledge_recipient_consent,
                        large_ack=args.acknowledge_large_transaction,
                    )
                )
                return 0
            if args.plan_out is None:
                raise MintError("prepare --execute requires --plan-out")
            if not args.wallet:
                raise MintError("prepare --execute requires --wallet")
            if args.chain == "main" and args.acknowledge_mainnet != MAINNET_PREPARE_ACK:
                raise MintError(
                    f"mainnet preparation requires --acknowledge-mainnet {MAINNET_PREPARE_ACK!r}"
                )
            resolved_plan = args.plan_out.expanduser().resolve()
            journal_path = execution_journal_path(resolved_plan)
            if resolved_plan.exists():
                raise MintError(f"refusing to overwrite existing plan: {resolved_plan}")
            if journal_path.exists():
                raise MintError(f"refusing to overwrite existing journal: {journal_path}")
            wallet_info = _require_dict(
                rpc.call("getwalletinfo"), "getwalletinfo result"
            )
            wallet_name = wallet_info.get("walletname")
            if not isinstance(wallet_name, str):
                raise MintError("funding wallet did not report its exact wallet name")
            reservation_id = secrets.token_hex(16)
            plan: dict[str, Any] | None = None
            genesis = MAINNET_GENESIS if args.chain == "main" else REGTEST_GENESIS
            with ExecutionJournal.create(
                journal_path,
                reservation_id=reservation_id,
                chain=args.chain,
                genesis=genesis,
                wallet_name=wallet_name,
            ) as journal:
                try:
                    plan = prepare_plan(
                        rpc,
                        content=content,
                        artifact_name=args.artifact.name,
                        mime=args.mime,
                        recipients=recipients,
                        chain=args.chain,
                        fee_rate=fee_rate,
                        max_fee_rate=max_fee_rate,
                        max_carriers=args.max_carriers,
                        max_funding_fee_sats=args.max_funding_fee_sats,
                        max_reveal_fee_sats=args.max_reveal_fee_sats,
                        max_total_fee_sats=args.max_total_fee_sats,
                        max_total_spend_sats=args.max_total_spend_sats,
                        consent_ack=args.acknowledge_recipient_consent,
                        large_ack=args.acknowledge_large_transaction,
                        reservation_id=reservation_id,
                        wallet_name=wallet_name,
                        on_inputs_selected=journal.record_inputs_selected,
                        on_locks_persisted=journal.record_locks_persisted,
                    )
                    write_new_private_json(resolved_plan, plan)
                    journal.commit_plan(plan)
                except BaseException as exc:
                    if plan is not None:
                        reserved = [
                            wallet_input
                            for entry in plan["entries"]
                            for wallet_input in entry["funding"]["locked_wallet_inputs"]
                        ]
                        primary = exc
                        if isinstance(exc, LockCleanupError):
                            reserved.extend(exc.candidates)
                            primary = exc.primary
                        _cleanup_reserved_after_failure(rpc, reserved, primary)
                        if primary is not exc:
                            raise primary
                    raise
            _print_json(
                {
                    "status": "prepared-not-broadcast",
                    "plan": str(resolved_plan),
                    "journal": str(journal_path),
                    "plan_id": plan["plan_id"],
                    "plan_checksum": plan["checksum_blake2b256"],
                    "totals": plan["totals"],
                    "next": "broadcast funding only after independently reviewing the plan",
                }
            )
            return 0
        with locked_plan(args.plan) as plan:
            if args.command == "broadcast":
                with ExecutionJournal.open(
                    execution_journal_path(args.plan)
                ) as journal:
                    result = broadcast_plan_stage(
                        rpc,
                        plan,
                        stage=args.stage,
                        selection=args.entry,
                        execute=args.execute,
                        acknowledgement=args.acknowledge,
                        approved_plan_checksum=args.approve_plan_checksum,
                        refund_acknowledgement=args.acknowledge_refund,
                        min_confirmations=args.min_confirmations,
                        journal=journal,
                    )
                _print_json(result)
                return 0
            if args.command == "status":
                _print_json(plan_status(rpc, plan))
                return 0
            if args.command == "unlock":
                with ExecutionJournal.open(
                    execution_journal_path(args.plan)
                ) as journal:
                    unlocked = unlock_plan_inputs(
                        rpc,
                        plan,
                        selection=args.entry,
                        journal=journal,
                        execute=args.execute,
                        acknowledgement=args.acknowledge,
                    )
                _print_json(unlocked)
                return 0
        raise AssertionError("unhandled command")
    except (MintError, OSError, ValueError, KeyError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
