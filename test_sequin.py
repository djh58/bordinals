#!/usr/bin/env python3
"""Pure-Python tests for the SEQUIN wire codec."""

from __future__ import annotations

import hashlib
import random
import unittest

from sequin import (
    MAX_MIME_BYTES,
    SequinError,
    build_manifest,
    carrier_count,
    decode_content,
    decode_sequences,
    encode_sequences,
    extract_op_return_payload,
    op_return_script,
    parse_manifest,
)


class SequinCodecTest(unittest.TestCase):
    def test_round_trip_boundary_lengths(self) -> None:
        rng = random.Random(0x5E9011)
        for length in [1, 2, 3, 4, 7, 14, 15, 16, 29, 30, 31, 75, 80, 255, 1024]:
            with self.subTest(length=length):
                content = rng.randbytes(length)
                sequences = encode_sequences(content)
                self.assertEqual(len(sequences), carrier_count(length))
                self.assertEqual(decode_sequences(sequences, length), content)

    def test_all_uint32_patterns_are_payload(self) -> None:
        content = bytes.fromhex("00000000fdfffffffeffffffffffffff")
        self.assertEqual(
            encode_sequences(content),
            [0x00000000, 0xFFFFFFFD, 0xFFFFFFFE, 0xFFFFFFFF],
        )
        self.assertEqual(decode_sequences(encode_sequences(content), len(content)), content)

    def test_manifest_and_op_return_round_trip(self) -> None:
        content = bytes(range(256)) + b"\x00\xffSEQUIN"
        manifest_bytes = build_manifest(content, "application/octet-stream")
        script = op_return_script(manifest_bytes)
        self.assertLessEqual(len(manifest_bytes), 80)
        self.assertLessEqual(len(script), 83)
        self.assertEqual(extract_op_return_payload(script), manifest_bytes)
        manifest = parse_manifest(manifest_bytes)
        self.assertEqual(manifest.content_sha256, hashlib.sha256(content).digest())
        self.assertEqual(decode_content(manifest_bytes, encode_sequences(content)), content)

    def test_eighty_byte_manifest_uses_minimal_pushdata1(self) -> None:
        content = b"x"
        manifest = build_manifest(content, "m" * MAX_MIME_BYTES)
        self.assertEqual(len(manifest), 80)
        script = op_return_script(manifest)
        self.assertEqual(script[:3], b"\x6a\x4c\x50")
        self.assertEqual(len(script), 83)

    def test_nonzero_padding_is_rejected(self) -> None:
        content = b"x"
        sequences = encode_sequences(content)
        sequences[-1] |= 1 << 20
        with self.assertRaisesRegex(SequinError, "non-zero padding"):
            decode_sequences(sequences, len(content))

    def test_hash_mismatch_is_rejected(self) -> None:
        content = b"byte perfect"
        manifest = bytearray(build_manifest(content, "text/plain"))
        manifest[16] ^= 1  # First byte of SHA256 in the packed v1 header.
        with self.assertRaisesRegex(SequinError, "SHA256"):
            decode_content(bytes(manifest), encode_sequences(content))


if __name__ == "__main__":
    unittest.main()
