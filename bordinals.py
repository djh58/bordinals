#!/usr/bin/env python3
"""Canonical BORDINALS framing and P2WSH script construction.

BORDINALS places opaque bytes in executed P2WSH witness scripts.  Each carrier
has six minimally encoded 250-byte pushes, with each adjacent pair consumed by
``OP_2DROP``. A compressed secp256k1 public key and ``OP_CHECKSIG`` form the
trailing spend condition, so revealing the carrier requires a valid signature.

The fixed shape is deliberate.  A local carrier index makes scripts unique even
when an artifact has repeated 1,500-byte regions.  With a conservative 73-byte
SegWit-v0 ECDSA signature budget, the complete serialized witness is 1,639
bytes, below the 1,650-byte default script/witness policy limit in the audited
Knots v29.4.1 code. These are policy properties, not consensus guarantees, and a
future policy rule that counts data discarded by OP_2DROP can make the
construction nonstandard.

This module uses only Python's standard library.  It constructs and strictly
parses scripts but does not create transactions or signatures.
"""

from __future__ import annotations

import argparse
from dataclasses import dataclass
import hashlib
import json
from pathlib import Path
import struct
from typing import Sequence


NAME = "BORDINALS"
MAGIC = b"BORD"
VERSION = 1
FLAGS_RAW = 0

# Canonical carrier geometry.  BIP-110/RDTS permits stack elements up to 256
# bytes; 250 leaves a little margin while making every push use OP_PUSHDATA1.
CHUNK_BYTES = 250
CHUNKS_PER_SCRIPT = 6
CHUNKS_PER_PAIR = 2
PAIRS_PER_SCRIPT = CHUNKS_PER_SCRIPT // CHUNKS_PER_PAIR
MAX_PAYLOAD_BYTES = CHUNK_BYTES * CHUNKS_PER_SCRIPT
CARRIER_INDEX_BYTES = 4
CARRIER_TAG = b"BOR1"

# Script opcodes used by the single accepted v1 template.
OP_PUSHDATA1 = 0x4C
OP_2DROP = 0x6D
OP_CHECKSIG = 0xAC
OP_0 = 0x00

COMPRESSED_PUBKEY_BYTES = 33
SCRIPT_BYTES = (
    CHUNKS_PER_SCRIPT * (2 + CHUNK_BYTES)
    + PAIRS_PER_SCRIPT
    + 1 + CARRIER_INDEX_BYTES
    + 1 + len(CARRIER_TAG)
    + 1  # OP_2DROP for the index/tag pair.
    + 1 + COMPRESSED_PUBKEY_BYTES
    + 1
)

# Audited Knots 29.x policy budgets.  CompactSize encodings are included:
# stack count (1), signature length (1), signature (73), script length (3),
# and the fixed script.  Keep the arithmetic visible and regression-tested.
MAX_SIGNATURE_BYTES = 73
MAX_DEFAULT_WITNESS_BYTES = 1650
MAX_STANDARD_P2WSH_SCRIPT_BYTES = 3600
SERIALIZED_WITNESS_BYTES_MAX = (
    1 + 1 + MAX_SIGNATURE_BYTES + 3 + SCRIPT_BYTES
)
assert SCRIPT_BYTES == 1561
assert SERIALIZED_WITNESS_BYTES_MAX == 1639
assert SCRIPT_BYTES <= MAX_STANDARD_P2WSH_SCRIPT_BYTES
assert SERIALIZED_WITNESS_BYTES_MAX <= MAX_DEFAULT_WITNESS_BYTES

# One standard OP_RETURN carries transaction-level framing.  The manifest
# layout is little-endian and mirrors SEQUIN's fields:
# magic, version, flags, first input, input count, pointer vout, content length,
# BLAKE2b-256, MIME length, then MIME ASCII bytes.
MAX_OP_RETURN_PAYLOAD = 80
MANIFEST_HEADER = struct.Struct("<4sBBHHHI32sB")
MAX_MIME_BYTES = MAX_OP_RETURN_PAYLOAD - MANIFEST_HEADER.size

_SECP256K1_FIELD = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F
_SECP256K1_ORDER = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
SIGHASH_ALL = 0x01
SIGHASH_UNIFIED = 0x20
BORDINALS_SIGHASH = SIGHASH_ALL | SIGHASH_UNIFIED


class BordinalsError(ValueError):
    """Raised for malformed or non-canonical BORDINALS data."""


@dataclass(frozen=True)
class Manifest:
    version: int
    flags: int
    first_input: int
    input_count: int
    pointer_vout: int
    content_length: int
    content_blake2b256: bytes
    mime: str

    def to_dict(self) -> dict[str, object]:
        return {
            "protocol": NAME,
            "version": self.version,
            "flags": self.flags,
            "first_input": self.first_input,
            "input_count": self.input_count,
            "pointer_vout": self.pointer_vout,
            "content_length": self.content_length,
            "content_blake2b256": self.content_blake2b256.hex(),
            "mime": self.mime,
        }


def carrier_count(content_length: int) -> int:
    """Return the canonical number of fixed-size carrier scripts."""
    if content_length <= 0:
        raise BordinalsError("content must contain at least one byte")
    return (content_length + MAX_PAYLOAD_BYTES - 1) // MAX_PAYLOAD_BYTES


def encode_payloads(content: bytes) -> list[bytes]:
    """Split content into 1,500-byte payloads with canonical trailing zeros."""
    count = carrier_count(len(content))
    return [
        content[offset:offset + MAX_PAYLOAD_BYTES].ljust(MAX_PAYLOAD_BYTES, b"\x00")
        for offset in range(0, count * MAX_PAYLOAD_BYTES, MAX_PAYLOAD_BYTES)
    ]


def _validate_pubkey(pubkey: bytes) -> None:
    """Validate a compressed secp256k1 point without external dependencies."""
    if len(pubkey) != COMPRESSED_PUBKEY_BYTES or pubkey[0] not in (2, 3):
        raise BordinalsError("spend key must be a 33-byte compressed public key")
    x = int.from_bytes(pubkey[1:], "big")
    if x >= _SECP256K1_FIELD:
        raise BordinalsError("compressed public key x-coordinate is out of range")
    y_squared = (pow(x, 3, _SECP256K1_FIELD) + 7) % _SECP256K1_FIELD
    y = pow(y_squared, (_SECP256K1_FIELD + 1) // 4, _SECP256K1_FIELD)
    if pow(y, 2, _SECP256K1_FIELD) != y_squared:
        raise BordinalsError("compressed public key is not on secp256k1")


def build_script(payload: bytes, pubkey: bytes, *, carrier_index: int = 0) -> bytes:
    """Build the sole canonical v1 carrier script.

    ``payload`` may contain 1..1,500 bytes and is zero-padded to the fixed
    carrier size.  Callers encoding a complete artifact normally use the
    already padded values returned by :func:`encode_payloads`.
    """
    if not payload or len(payload) > MAX_PAYLOAD_BYTES:
        raise BordinalsError(
            f"carrier payload must be 1..{MAX_PAYLOAD_BYTES} bytes"
        )
    _validate_pubkey(pubkey)
    if not 0 <= carrier_index <= 0xFFFFFFFF:
        raise BordinalsError("carrier_index does not fit uint32")
    padded = payload.ljust(MAX_PAYLOAD_BYTES, b"\x00")

    script = bytearray()
    for index in range(CHUNKS_PER_SCRIPT):
        start = index * CHUNK_BYTES
        script.extend((OP_PUSHDATA1, CHUNK_BYTES))
        script.extend(padded[start:start + CHUNK_BYTES])
        if index % CHUNKS_PER_PAIR == CHUNKS_PER_PAIR - 1:
            script.append(OP_2DROP)
    script.append(CARRIER_INDEX_BYTES)  # Minimal direct push.
    script.extend(carrier_index.to_bytes(CARRIER_INDEX_BYTES, "little"))
    script.append(len(CARRIER_TAG))  # Minimal direct push.
    script.extend(CARRIER_TAG)
    script.append(OP_2DROP)
    script.append(COMPRESSED_PUBKEY_BYTES)  # Minimal direct push.
    script.extend(pubkey)
    script.append(OP_CHECKSIG)
    if len(script) != SCRIPT_BYTES:
        raise AssertionError("BORDINALS script geometry changed unexpectedly")
    return bytes(script)


def _parse_script(script: bytes) -> tuple[bytes, bytes, int]:
    """Return ``(padded_payload, pubkey, carrier_index)`` after validation."""
    if len(script) != SCRIPT_BYTES:
        raise BordinalsError(
            f"carrier script must be exactly {SCRIPT_BYTES} bytes"
        )

    cursor = 0
    chunks: list[bytes] = []
    for index in range(CHUNKS_PER_SCRIPT):
        if script[cursor:cursor + 2] != bytes((OP_PUSHDATA1, CHUNK_BYTES)):
            raise BordinalsError(
                f"chunk {index} is not a canonical {CHUNK_BYTES}-byte push"
            )
        cursor += 2
        chunks.append(script[cursor:cursor + CHUNK_BYTES])
        cursor += CHUNK_BYTES
        if index % CHUNKS_PER_PAIR == CHUNKS_PER_PAIR - 1:
            if script[cursor] != OP_2DROP:
                raise BordinalsError(
                    f"chunk pair {index // CHUNKS_PER_PAIR} lacks OP_2DROP"
                )
            cursor += 1

    if script[cursor] != CARRIER_INDEX_BYTES:
        raise BordinalsError("carrier index is not a canonical four-byte push")
    cursor += 1
    carrier_index = int.from_bytes(
        script[cursor:cursor + CARRIER_INDEX_BYTES], "little"
    )
    cursor += CARRIER_INDEX_BYTES
    if script[cursor] != len(CARRIER_TAG):
        raise BordinalsError("carrier domain tag is not minimally pushed")
    cursor += 1
    if script[cursor:cursor + len(CARRIER_TAG)] != CARRIER_TAG:
        raise BordinalsError("carrier domain tag is invalid")
    cursor += len(CARRIER_TAG)
    if script[cursor] != OP_2DROP:
        raise BordinalsError("carrier index/tag pair lacks OP_2DROP")
    cursor += 1

    if script[cursor] != COMPRESSED_PUBKEY_BYTES:
        raise BordinalsError("spend key is not minimally pushed")
    cursor += 1
    pubkey = script[cursor:cursor + COMPRESSED_PUBKEY_BYTES]
    cursor += COMPRESSED_PUBKEY_BYTES
    _validate_pubkey(pubkey)
    if script[cursor] != OP_CHECKSIG:
        raise BordinalsError("carrier lacks its trailing OP_CHECKSIG")
    cursor += 1
    if cursor != len(script):
        raise BordinalsError("carrier has trailing script instructions")
    return b"".join(chunks), pubkey, carrier_index


def parse_script(
    script: bytes,
    *,
    expected_pubkey: bytes | None = None,
    expected_index: int | None = None,
) -> bytes:
    """Strictly parse a carrier and return its padded 1,500-byte payload."""
    payload, pubkey, carrier_index = _parse_script(script)
    if expected_pubkey is not None:
        _validate_pubkey(expected_pubkey)
        if pubkey != expected_pubkey:
            raise BordinalsError("carrier spend key does not match the expected key")
    if expected_index is not None and carrier_index != expected_index:
        raise BordinalsError(
            f"carrier index {carrier_index} does not match expected index {expected_index}"
        )
    return payload


def p2wsh_scriptpubkey(script: bytes) -> bytes:
    """Return the native SegWit-v0 P2WSH scriptPubKey for a valid carrier."""
    _parse_script(script)
    scriptpubkey = bytes((OP_0, 32)) + hashlib.sha256(script).digest()
    if has_olga_marker(scriptpubkey):
        raise BordinalsError(
            "P2WSH hash accidentally matches Knots' OLGA marker; choose another spend key"
        )
    return scriptpubkey


def has_olga_marker(scriptpubkey: bytes) -> bool:
    """Return whether a P2WSH output has Knots' case-insensitive ``stamp:`` marker.

    Knots' OLGA detector also considers output position and a length encoded in
    the first two witness-program bytes.  Rejecting every matching prefix is a
    simpler, conservative encoder rule: changing the spend key changes the
    P2WSH hash without changing the artifact.
    """
    return (
        len(scriptpubkey) == 34
        and scriptpubkey[:2] == bytes((OP_0, 32))
        and bytes(byte | 0x20 for byte in scriptpubkey[4:9]) == b"stamp"
        and scriptpubkey[9] == ord(":")
    )


def build_manifest(
    content: bytes,
    mime: str,
    *,
    first_input: int = 0,
    input_count: int | None = None,
    pointer_vout: int = 0,
) -> bytes:
    """Build the manifest that must appear identically in funding and reveal."""
    try:
        mime_bytes = mime.encode("ascii")
    except UnicodeEncodeError as exc:
        raise BordinalsError("MIME type must be ASCII") from exc
    if not mime_bytes or len(mime_bytes) > MAX_MIME_BYTES:
        raise BordinalsError(
            f"MIME type must be 1..{MAX_MIME_BYTES} ASCII bytes"
        )
    if any(byte < 0x21 or byte > 0x7E for byte in mime_bytes):
        raise BordinalsError("MIME type must use visible ASCII without spaces")
    if not 0 <= first_input <= 0xFFFF:
        raise BordinalsError("first_input does not fit uint16")
    if not 0 <= pointer_vout <= 0xFFFF:
        raise BordinalsError("pointer_vout does not fit uint16")
    if len(content) > 0xFFFFFFFF:
        raise BordinalsError("content is too large for the v1 manifest")

    canonical_count = carrier_count(len(content))
    if input_count is None:
        input_count = canonical_count
    if input_count != canonical_count:
        raise BordinalsError("input_count is non-canonical for the content length")
    if input_count > 0xFFFF or first_input + input_count > 0x10000:
        raise BordinalsError("carrier input range does not fit the v1 manifest")

    header = MANIFEST_HEADER.pack(
        MAGIC,
        VERSION,
        FLAGS_RAW,
        first_input,
        input_count,
        pointer_vout,
        len(content),
        hashlib.blake2b(content, digest_size=32).digest(),
        len(mime_bytes),
    )
    manifest = header + mime_bytes
    if len(manifest) > MAX_OP_RETURN_PAYLOAD:
        raise AssertionError("manifest exceeded the OP_RETURN payload limit")
    return manifest


def parse_manifest(payload: bytes) -> Manifest:
    """Parse and strictly validate a binary v1 manifest."""
    if len(payload) < MANIFEST_HEADER.size:
        raise BordinalsError("manifest is truncated")
    if len(payload) > MAX_OP_RETURN_PAYLOAD:
        raise BordinalsError("manifest exceeds the 80-byte OP_RETURN payload limit")

    (
        magic,
        version,
        flags,
        first_input,
        input_count,
        pointer_vout,
        content_length,
        digest,
        mime_length,
    ) = MANIFEST_HEADER.unpack_from(payload)
    if magic != MAGIC:
        raise BordinalsError("not a BORDINALS manifest")
    if version != VERSION:
        raise BordinalsError(f"unsupported BORDINALS version {version}")
    if flags != FLAGS_RAW:
        raise BordinalsError(f"unsupported BORDINALS flags 0x{flags:02x}")
    if len(payload) != MANIFEST_HEADER.size + mime_length:
        raise BordinalsError("manifest MIME length is inconsistent")
    if input_count != carrier_count(content_length):
        raise BordinalsError("manifest input count is non-canonical")
    if first_input + input_count > 0x10000:
        raise BordinalsError("manifest carrier input range overflows uint16")

    mime_bytes = payload[MANIFEST_HEADER.size:]
    try:
        mime = mime_bytes.decode("ascii")
    except UnicodeDecodeError as exc:
        raise BordinalsError("manifest MIME type is not ASCII") from exc
    if not mime or any(byte < 0x21 or byte > 0x7E for byte in mime_bytes):
        raise BordinalsError("manifest MIME type is not canonical visible ASCII")

    return Manifest(
        version=version,
        flags=flags,
        first_input=first_input,
        input_count=input_count,
        pointer_vout=pointer_vout,
        content_length=content_length,
        content_blake2b256=digest,
        mime=mime,
    )


def decode_content(
    manifest_payload: bytes,
    all_scripts: Sequence[bytes],
    *,
    expected_pubkey: bytes | None = None,
) -> bytes:
    """Reconstruct content from already-authenticated scripts in input order.

    This low-level helper does not inspect signatures or the funding manifest.
    Indexers decoding raw transactions should call
    :func:`decode_committed_witnesses` instead.
    """
    manifest = parse_manifest(manifest_payload)
    stop = manifest.first_input + manifest.input_count
    if stop > len(all_scripts):
        raise BordinalsError("reveal transaction has fewer inputs than its manifest")

    selected = all_scripts[manifest.first_input:stop]
    decoded = bytearray()
    common_pubkey = expected_pubkey
    for index, script in enumerate(selected):
        payload, pubkey, carrier_index = _parse_script(script)
        if carrier_index != index:
            raise BordinalsError(
                f"carrier {index} declares non-canonical index {carrier_index}"
            )
        if common_pubkey is None:
            common_pubkey = pubkey
        elif pubkey != common_pubkey:
            raise BordinalsError(f"carrier {index} uses a different spend key")
        decoded.extend(payload)

    content = bytes(decoded[:manifest.content_length])
    if any(decoded[manifest.content_length:]):
        raise BordinalsError("non-zero carrier padding is non-canonical")
    if (
        hashlib.blake2b(content, digest_size=32).digest()
        != manifest.content_blake2b256
    ):
        raise BordinalsError(
            "decoded content BLAKE2b-256 does not match the manifest"
        )
    return content


def validate_signature_item(signature: bytes) -> None:
    """Require strict DER/low-S ECDSA with unified SIGHASH_ALL (0x21).

    This validates canonical framing, not the ECDSA equation. A decoder must
    obtain the witness from a consensus-validated transaction (or separately
    verify it against the transaction and P2WSH prevout) before accepting an
    artifact.
    """
    if len(signature) < 9 or len(signature) > 73:
        raise BordinalsError("carrier signature length is not strict DER")
    if signature[-1] != BORDINALS_SIGHASH:
        raise BordinalsError(
            "carrier signature must use SIGHASH_ALL|SIGHASH_UNIFIED (0x21)"
        )

    der = signature[:-1]
    if der[0] != 0x30 or der[1] != len(der) - 2:
        raise BordinalsError("carrier signature has an invalid DER sequence")
    if len(der) < 6 or der[2] != 0x02:
        raise BordinalsError("carrier signature has an invalid DER R integer")

    r_length = der[3]
    r_start = 4
    r_end = r_start + r_length
    if r_length == 0 or r_end + 2 > len(der) or der[r_end] != 0x02:
        raise BordinalsError("carrier signature has an invalid DER R length")
    r_bytes = der[r_start:r_end]
    if r_bytes[0] & 0x80 or (
        len(r_bytes) > 1 and r_bytes[0] == 0 and not r_bytes[1] & 0x80
    ):
        raise BordinalsError("carrier signature R is negative or non-minimal")

    s_length = der[r_end + 1]
    s_start = r_end + 2
    s_end = s_start + s_length
    if s_length == 0 or s_end != len(der):
        raise BordinalsError("carrier signature has an invalid DER S length")
    s_bytes = der[s_start:s_end]
    if s_bytes[0] & 0x80 or (
        len(s_bytes) > 1 and s_bytes[0] == 0 and not s_bytes[1] & 0x80
    ):
        raise BordinalsError("carrier signature S is negative or non-minimal")

    r = int.from_bytes(r_bytes, "big")
    s = int.from_bytes(s_bytes, "big")
    if not 1 <= r < _SECP256K1_ORDER:
        raise BordinalsError("carrier signature R is outside the curve order")
    if not 1 <= s <= _SECP256K1_ORDER // 2:
        raise BordinalsError("carrier signature is not low-S")


def decode_witnesses(
    manifest_payload: bytes,
    all_witnesses: Sequence[Sequence[bytes]],
    *,
    expected_pubkey: bytes | None = None,
) -> bytes:
    """Decode canonical carrier witnesses selected by one trusted manifest.

    Each selected P2WSH witness must contain exactly ``[signature, script]``.
    Requiring unified SIGHASH_ALL makes every carrier signature commit to all
    spent outputs, reveal inputs, sequences, and outputs, including the
    manifest and pointer, while opting into Knots fork replay protection.

    This lower-level helper assumes the caller has already established which
    manifest the funding transaction committed. Transaction/indexer code should
    normally call :func:`decode_committed_witnesses` instead.
    """
    manifest = parse_manifest(manifest_payload)
    stop = manifest.first_input + manifest.input_count
    if stop > len(all_witnesses):
        raise BordinalsError("reveal transaction has fewer inputs than its manifest")

    all_scripts = [b""] * len(all_witnesses)
    for input_index in range(manifest.first_input, stop):
        witness = all_witnesses[input_index]
        if len(witness) != 2:
            raise BordinalsError(
                f"carrier input {input_index} witness must contain signature and script"
            )
        signature, script = witness
        validate_signature_item(signature)
        all_scripts[input_index] = script
    return decode_content(
        manifest_payload,
        all_scripts,
        expected_pubkey=expected_pubkey,
    )


def decode_committed_witnesses(
    funding_manifest_payload: bytes,
    reveal_manifest_payload: bytes,
    all_witnesses: Sequence[Sequence[bytes]],
    *,
    expected_pubkey: bytes | None = None,
) -> bytes:
    """Decode witnesses only when funding and reveal repeat one exact manifest.

    The caller must extract ``funding_manifest_payload`` from the single common
    funding transaction that created every selected carrier and
    ``reveal_manifest_payload`` from the consensus-validated reveal. This
    helper validates both manifests and requires byte-for-byte equality before
    accepting the signed reveal witnesses. It does not itself fetch
    transactions, verify prevout ancestry, or evaluate ECDSA signatures.
    """
    parse_manifest(funding_manifest_payload)
    parse_manifest(reveal_manifest_payload)
    if funding_manifest_payload != reveal_manifest_payload:
        raise BordinalsError(
            "funding and reveal manifests must be byte-identical"
        )
    return decode_witnesses(
        reveal_manifest_payload,
        all_witnesses,
        expected_pubkey=expected_pubkey,
    )


def op_return_script(manifest_payload: bytes) -> bytes:
    """Return a minimally encoded OP_RETURN script for a manifest."""
    size = len(manifest_payload)
    if size > MAX_OP_RETURN_PAYLOAD:
        raise BordinalsError("OP_RETURN payload exceeds 80 bytes")
    if size <= 75:
        return b"\x6a" + bytes((size,)) + manifest_payload
    return b"\x6a\x4c" + bytes((size,)) + manifest_payload


def extract_op_return_payload(script: bytes) -> bytes:
    """Extract one minimally pushed, at-most-80-byte OP_RETURN payload."""
    if not script or script[0] != 0x6A:
        raise BordinalsError("script is not OP_RETURN")
    if len(script) < 2:
        raise BordinalsError("OP_RETURN script has no push")
    opcode = script[1]
    if opcode <= 75:
        size, offset = opcode, 2
    elif opcode == OP_PUSHDATA1 and len(script) >= 3:
        size, offset = script[2], 3
        if size <= 75:
            raise BordinalsError("OP_PUSHDATA1 use is non-minimal")
    else:
        raise BordinalsError("OP_RETURN manifest is not a single minimal data push")
    if size > MAX_OP_RETURN_PAYLOAD or len(script) != offset + size:
        raise BordinalsError("OP_RETURN push length is inconsistent")
    return script[offset:]


def _encode_command(path: Path, mime: str, pubkey_hex: str) -> None:
    content = path.read_bytes()
    pubkey = bytes.fromhex(pubkey_hex)
    scripts = [
        build_script(payload, pubkey, carrier_index=index)
        for index, payload in enumerate(encode_payloads(content))
    ]
    manifest = build_manifest(content, mime, input_count=len(scripts))
    result = {
        "manifest": parse_manifest(manifest).to_dict(),
        "manifest_hex": manifest.hex(),
        "op_return_script_hex": op_return_script(manifest).hex(),
        "payload_bytes_per_input": MAX_PAYLOAD_BYTES,
        "carrier_scripts_hex": [script.hex() for script in scripts],
        "p2wsh_scriptpubkeys_hex": [
            p2wsh_scriptpubkey(script).hex() for script in scripts
        ],
    }
    print(json.dumps(result, indent=2))


def _decode_command(
    funding_manifest_hex: str,
    reveal_manifest_hex: str,
    witness_args: Sequence[str],
    output: Path,
    pubkey_hex: str | None,
) -> None:
    expected_pubkey = bytes.fromhex(pubkey_hex) if pubkey_hex is not None else None
    witnesses: list[list[bytes]] = []
    for argument in witness_args:
        signature_hex, separator, script_hex = argument.partition(":")
        if not separator:
            raise BordinalsError(
                "each witness must be SIGNATURE_HEX:WITNESS_SCRIPT_HEX"
            )
        witnesses.append([bytes.fromhex(signature_hex), bytes.fromhex(script_hex)])
    content = decode_committed_witnesses(
        bytes.fromhex(funding_manifest_hex),
        bytes.fromhex(reveal_manifest_hex),
        witnesses,
        expected_pubkey=expected_pubkey,
    )
    output.write_bytes(content)
    print(
        f"wrote {len(content)} hash-verified bytes from structurally canonical "
        f"witnesses to {output}"
    )


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    subparsers = parser.add_subparsers(dest="command", required=True)

    encode_parser = subparsers.add_parser("encode", help="encode a file")
    encode_parser.add_argument("file", type=Path)
    encode_parser.add_argument(
        "--pubkey",
        required=True,
        help="compressed secp256k1 public key hex controlling every carrier",
    )
    encode_parser.add_argument("--mime", default="application/octet-stream")

    decode_parser = subparsers.add_parser("decode", help="decode carrier witnesses")
    decode_parser.add_argument(
        "--funding-manifest",
        required=True,
        help="manifest hex extracted from the common funding transaction",
    )
    decode_parser.add_argument(
        "--reveal-manifest",
        "--manifest",
        dest="reveal_manifest",
        required=True,
        help="identical manifest hex extracted from the reveal transaction",
    )
    decode_parser.add_argument("--output", required=True, type=Path)
    decode_parser.add_argument(
        "--pubkey",
        help="optional expected compressed secp256k1 public key hex",
    )
    decode_parser.add_argument(
        "witnesses",
        nargs="+",
        help="SIGNATURE_HEX:WITNESS_SCRIPT_HEX for each reveal input",
    )

    args = parser.parse_args()
    if args.command == "encode":
        _encode_command(args.file, args.mime, args.pubkey)
    else:
        _decode_command(
            args.funding_manifest,
            args.reveal_manifest,
            args.witnesses,
            args.output,
            args.pubkey,
        )


if __name__ == "__main__":
    main()
