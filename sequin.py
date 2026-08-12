#!/usr/bin/env python3
"""SEQUIN: a small nSequence inscription codec.

SEQUIN stores a raw byte stream in the nSequence values of ordinary transaction
inputs.  A version-1 transaction with nLockTime zero gives nSequence no
consensus lock-time meaning, so all 32 bits are available.  Each four-byte
content chunk is interpreted little-endian, exactly matching transaction wire
serialization.

The reveal transaction also has one standard OP_RETURN output containing a
compact manifest.  The manifest supplies the exact byte length and SHA256 so
padding can be removed and decoding can be checked byte-for-byte.

This module deliberately knows nothing about wallets or RPC.  It is suitable
for indexers, offline construction tools, and the accompanying regtest proof.
"""

from __future__ import annotations

import argparse
from dataclasses import dataclass
import hashlib
import json
from pathlib import Path
import struct
from typing import Iterable, Sequence


NAME = "SEQUIN"
MAGIC = b"SEQN"
VERSION = 1
FLAGS_RAW = 0

BYTES_PER_INPUT = 4

MAX_OP_RETURN_PAYLOAD = 80
MANIFEST_HEADER = struct.Struct("<4sBBHHHI32sB")
MAX_MIME_BYTES = MAX_OP_RETURN_PAYLOAD - MANIFEST_HEADER.size


class SequinError(ValueError):
    """Raised for malformed or non-canonical SEQUIN data."""


@dataclass(frozen=True)
class Manifest:
    version: int
    flags: int
    first_input: int
    input_count: int
    pointer_vout: int
    content_length: int
    content_sha256: bytes
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
            "content_sha256": self.content_sha256.hex(),
            "mime": self.mime,
        }


def carrier_count(content_length: int) -> int:
    """Return the canonical number of four-byte carrier inputs."""
    if content_length <= 0:
        raise SequinError("content must contain at least one byte")
    return (content_length + BYTES_PER_INPUT - 1) // BYTES_PER_INPUT


def encode_sequences(content: bytes) -> list[int]:
    """Pack content into uint32 values with byte order matching the tx wire."""
    carrier_count(len(content))  # Validate non-empty content.
    return [
        int.from_bytes(content[offset:offset + 4].ljust(4, b"\x00"), "little")
        for offset in range(0, len(content), 4)
    ]


def decode_sequences(sequences: Iterable[int], content_length: int) -> bytes:
    """Decode and strictly validate a canonical SEQUIN sequence stream."""
    values = list(sequences)
    expected_count = carrier_count(content_length)
    if len(values) != expected_count:
        raise SequinError(
            f"manifest requires {expected_count} carrier inputs, got {len(values)}"
        )

    encoded = bytearray()
    for index, sequence in enumerate(values):
        if not 0 <= sequence <= 0xFFFFFFFF:
            raise SequinError(f"input {index} nSequence is outside uint32")
        encoded.extend(sequence.to_bytes(BYTES_PER_INPUT, "little"))

    decoded = bytes(encoded[:content_length])
    if any(encoded[content_length:]):
        raise SequinError("non-zero padding makes the sequence stream non-canonical")
    return decoded


def build_manifest(
    content: bytes,
    mime: str,
    *,
    first_input: int = 0,
    pointer_vout: int = 0,
) -> bytes:
    """Build the binary payload carried by the reveal's OP_RETURN output."""
    try:
        mime_bytes = mime.encode("ascii")
    except UnicodeEncodeError as exc:
        raise SequinError("MIME type must be ASCII") from exc

    if not mime_bytes or len(mime_bytes) > MAX_MIME_BYTES:
        raise SequinError(
            f"MIME type must be 1..{MAX_MIME_BYTES} ASCII bytes"
        )
    if not 0 <= first_input <= 0xFFFF:
        raise SequinError("first_input does not fit uint16")
    if not 0 <= pointer_vout <= 0xFFFF:
        raise SequinError("pointer_vout does not fit uint16")
    if len(content) > 0xFFFFFFFF:
        raise SequinError("content is too large for the v1 manifest")

    count = carrier_count(len(content))
    if count > 0xFFFF or first_input + count > 0x10000:
        raise SequinError("carrier input range does not fit the v1 manifest")

    header = MANIFEST_HEADER.pack(
        MAGIC,
        VERSION,
        FLAGS_RAW,
        first_input,
        count,
        pointer_vout,
        len(content),
        hashlib.sha256(content).digest(),
        len(mime_bytes),
    )
    manifest = header + mime_bytes
    if len(manifest) > MAX_OP_RETURN_PAYLOAD:
        raise AssertionError("manifest exceeded the OP_RETURN payload limit")
    return manifest


def parse_manifest(payload: bytes) -> Manifest:
    """Parse and strictly validate a v1 binary manifest payload."""
    if len(payload) < MANIFEST_HEADER.size:
        raise SequinError("manifest is truncated")
    if len(payload) > MAX_OP_RETURN_PAYLOAD:
        raise SequinError("manifest exceeds the 80-byte OP_RETURN payload limit")

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
        raise SequinError("not a SEQUIN manifest")
    if version != VERSION:
        raise SequinError(f"unsupported SEQUIN version {version}")
    if flags != FLAGS_RAW:
        raise SequinError(f"unsupported SEQUIN flags 0x{flags:02x}")
    if len(payload) != MANIFEST_HEADER.size + mime_length:
        raise SequinError("manifest MIME length is inconsistent")
    if input_count != carrier_count(content_length):
        raise SequinError("manifest input count is non-canonical")
    if first_input + input_count > 0x10000:
        raise SequinError("manifest carrier input range overflows uint16")

    mime_bytes = payload[MANIFEST_HEADER.size:]
    try:
        mime = mime_bytes.decode("ascii")
    except UnicodeDecodeError as exc:
        raise SequinError("manifest MIME type is not ASCII") from exc
    if not mime:
        raise SequinError("manifest MIME type is empty")

    return Manifest(
        version=version,
        flags=flags,
        first_input=first_input,
        input_count=input_count,
        pointer_vout=pointer_vout,
        content_length=content_length,
        content_sha256=digest,
        mime=mime,
    )


def decode_content(manifest_payload: bytes, all_sequences: Sequence[int]) -> bytes:
    """Decode content from a manifest and the reveal transaction's input order."""
    manifest = parse_manifest(manifest_payload)
    stop = manifest.first_input + manifest.input_count
    if stop > len(all_sequences):
        raise SequinError("reveal transaction has fewer inputs than its manifest")
    content = decode_sequences(
        all_sequences[manifest.first_input:stop], manifest.content_length
    )
    digest = hashlib.sha256(content).digest()
    if digest != manifest.content_sha256:
        raise SequinError("decoded content SHA256 does not match the manifest")
    return content


def op_return_script(manifest_payload: bytes) -> bytes:
    """Return the minimally encoded OP_RETURN script for a manifest."""
    size = len(manifest_payload)
    if size > MAX_OP_RETURN_PAYLOAD:
        raise SequinError("OP_RETURN payload exceeds 80 bytes")
    if size <= 75:
        return b"\x6a" + bytes([size]) + manifest_payload
    return b"\x6a\x4c" + bytes([size]) + manifest_payload


def extract_op_return_payload(script: bytes) -> bytes:
    """Extract a minimally pushed <=80-byte payload from an OP_RETURN script."""
    if not script or script[0] != 0x6A:
        raise SequinError("script is not OP_RETURN")
    if len(script) < 2:
        raise SequinError("OP_RETURN script has no push")

    opcode = script[1]
    if opcode <= 75:
        size = opcode
        offset = 2
    elif opcode == 0x4C and len(script) >= 3:
        size = script[2]
        offset = 3
        if size <= 75:
            raise SequinError("OP_PUSHDATA1 use is non-minimal")
    else:
        raise SequinError("OP_RETURN manifest is not a single minimal data push")

    if size > MAX_OP_RETURN_PAYLOAD or len(script) != offset + size:
        raise SequinError("OP_RETURN push length is inconsistent")
    return script[offset:]


def _encode_command(path: Path, mime: str) -> None:
    content = path.read_bytes()
    manifest = build_manifest(content, mime)
    result = {
        "manifest": parse_manifest(manifest).to_dict(),
        "manifest_hex": manifest.hex(),
        "op_return_script_hex": op_return_script(manifest).hex(),
        "sequences": [f"0x{value:08x}" for value in encode_sequences(content)],
    }
    print(json.dumps(result, indent=2))


def _decode_command(manifest_hex: str, sequence_args: Sequence[str], output: Path) -> None:
    manifest = bytes.fromhex(manifest_hex)
    sequences = [int(value, 0) for value in sequence_args]
    content = decode_content(manifest, sequences)
    output.write_bytes(content)
    print(f"wrote {len(content)} verified bytes to {output}")


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    subparsers = parser.add_subparsers(dest="command", required=True)

    encode_parser = subparsers.add_parser("encode", help="encode a file")
    encode_parser.add_argument("file", type=Path)
    encode_parser.add_argument("--mime", default="application/octet-stream")

    decode_parser = subparsers.add_parser("decode", help="decode sequence integers")
    decode_parser.add_argument("--manifest", required=True, help="manifest hex")
    decode_parser.add_argument("--output", required=True, type=Path)
    decode_parser.add_argument("sequences", nargs="+", help="decimal or 0x-prefixed nSequence values")

    args = parser.parse_args()
    if args.command == "encode":
        _encode_command(args.file, args.mime)
    else:
        _decode_command(args.manifest, args.sequences, args.output)


if __name__ == "__main__":
    main()
