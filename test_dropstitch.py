#!/usr/bin/env python3
"""Pure-Python tests for the canonical DROPSTITCH codec and script template."""

from __future__ import annotations

import hashlib
import random
import unittest

from dropstitch import (
    CHUNK_BYTES,
    CARRIER_INDEX_BYTES,
    CARRIER_TAG,
    MAX_DEFAULT_WITNESS_BYTES,
    MAX_MIME_BYTES,
    MAX_PAYLOAD_BYTES,
    OP_2DROP,
    OP_CHECKSIG,
    OP_PUSHDATA1,
    SCRIPT_BYTES,
    SERIALIZED_WITNESS_BYTES_MAX,
    DropstitchError,
    build_manifest,
    build_script,
    carrier_count,
    decode_committed_witnesses,
    decode_content,
    decode_witnesses,
    encode_payloads,
    extract_op_return_payload,
    has_olga_marker,
    op_return_script,
    p2wsh_scriptpubkey,
    parse_manifest,
    parse_script,
    validate_signature_item,
)


# Compressed secp256k1 generator point, a valid deterministic test key.
PUBKEY = bytes.fromhex(
    "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798"
)
# The same point with odd-y encoding is also a valid compressed public key,
# and is useful for testing key-binding without a crypto dependency.
OTHER_PUBKEY = bytes((3,)) + PUBKEY[1:]
# Structurally valid low-S DER values R=1, S=1, followed by SIGHASH_ALL.
CANONICAL_TEST_SIGNATURE = bytes.fromhex("300602010102010101")
_SECP256K1_HALF_ORDER_FOR_TEST = (
    0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141 // 2
)


class DropstitchCodecTest(unittest.TestCase):
    def test_round_trip_boundary_lengths(self) -> None:
        rng = random.Random(0xD09A5717)
        lengths = [
            1, 2, 249, 250, 251, 499, 500, 501,
            1499, 1500, 1501, 2999, 3000, 3001, 8192,
        ]
        for length in lengths:
            with self.subTest(length=length):
                content = rng.randbytes(length)
                payloads = encode_payloads(content)
                scripts = [
                    build_script(payload, PUBKEY, carrier_index=index)
                    for index, payload in enumerate(payloads)
                ]
                manifest = build_manifest(content, "application/octet-stream")
                self.assertEqual(len(payloads), carrier_count(length))
                self.assertTrue(all(len(item) == MAX_PAYLOAD_BYTES for item in payloads))
                self.assertEqual(decode_content(manifest, scripts), content)

    def test_script_shape_and_policy_budget(self) -> None:
        payload = bytes((index % 251 for index in range(MAX_PAYLOAD_BYTES)))
        script = build_script(payload, PUBKEY)
        self.assertEqual(len(script), SCRIPT_BYTES)
        self.assertEqual(SCRIPT_BYTES, 1561)
        self.assertEqual(SERIALIZED_WITNESS_BYTES_MAX, 1639)
        self.assertLessEqual(SERIALIZED_WITNESS_BYTES_MAX, MAX_DEFAULT_WITNESS_BYTES)
        self.assertEqual(
            parse_script(script, expected_pubkey=PUBKEY, expected_index=0),
            payload,
        )

        cursor = 0
        for index in range(6):
            self.assertEqual(script[cursor:cursor + 2], bytes((OP_PUSHDATA1, CHUNK_BYTES)))
            cursor += 2 + CHUNK_BYTES
            if index % 2 == 1:
                self.assertEqual(script[cursor], OP_2DROP)
                cursor += 1
        self.assertEqual(script[cursor], CARRIER_INDEX_BYTES)
        self.assertEqual(
            script[cursor + 1:cursor + 1 + CARRIER_INDEX_BYTES],
            b"\x00" * CARRIER_INDEX_BYTES,
        )
        cursor += 1 + CARRIER_INDEX_BYTES
        self.assertEqual(script[cursor], len(CARRIER_TAG))
        self.assertEqual(script[cursor + 1:cursor + 1 + len(CARRIER_TAG)], CARRIER_TAG)
        cursor += 1 + len(CARRIER_TAG)
        self.assertEqual(script[cursor], OP_2DROP)
        cursor += 1
        self.assertEqual(script[cursor], 33)
        self.assertEqual(script[cursor + 1:cursor + 34], PUBKEY)
        self.assertEqual(script[cursor + 34], OP_CHECKSIG)

    def test_short_payload_is_zero_padded(self) -> None:
        script = build_script(b"pixel", PUBKEY)
        payload = parse_script(script)
        self.assertEqual(payload[:5], b"pixel")
        self.assertEqual(payload[5:], b"\x00" * (MAX_PAYLOAD_BYTES - 5))

    def test_p2wsh_scriptpubkey(self) -> None:
        script = build_script(b"x", PUBKEY)
        self.assertEqual(
            p2wsh_scriptpubkey(script),
            b"\x00\x20" + hashlib.sha256(script).digest(),
        )

    def test_olga_marker_detection(self) -> None:
        self.assertTrue(
            has_olga_marker(b"\x00\x20\x12\x34StAmP:" + b"\x00" * 24)
        )
        self.assertFalse(
            has_olga_marker(b"\x00\x20\x12\x34stomp:" + b"\x00" * 24)
        )
        self.assertFalse(has_olga_marker(b"not a P2WSH scriptPubKey"))

    def test_manifest_and_op_return_round_trip(self) -> None:
        content = b"<svg/>" * 400
        manifest_bytes = build_manifest(
            content, "image/svg+xml", first_input=7, pointer_vout=2
        )
        manifest = parse_manifest(manifest_bytes)
        self.assertEqual(manifest.first_input, 7)
        self.assertEqual(manifest.input_count, carrier_count(len(content)))
        self.assertEqual(manifest.pointer_vout, 2)
        self.assertEqual(manifest.content_sha256, hashlib.sha256(content).digest())
        self.assertEqual(manifest.mime, "image/svg+xml")
        script = op_return_script(manifest_bytes)
        self.assertEqual(extract_op_return_payload(script), manifest_bytes)

    def test_eighty_byte_manifest_uses_minimal_pushdata1(self) -> None:
        manifest = build_manifest(b"x", "m" * MAX_MIME_BYTES)
        self.assertEqual(len(manifest), 80)
        script = op_return_script(manifest)
        self.assertEqual(script[:3], b"\x6a\x4c\x50")

    def test_input_range_selects_only_manifest_carriers(self) -> None:
        content = b"range-bound" * 200
        carriers = [
            build_script(part, PUBKEY, carrier_index=index)
            for index, part in enumerate(encode_payloads(content))
        ]
        unrelated = build_script(b"unrelated", OTHER_PUBKEY)
        manifest = build_manifest(content, "text/plain", first_input=1)
        self.assertEqual(
            decode_content(manifest, [unrelated, *carriers, unrelated]), content
        )

    def test_nonzero_padding_is_rejected(self) -> None:
        content = b"short"
        payload = bytearray(encode_payloads(content)[0])
        payload[-1] = 1
        script = build_script(bytes(payload), PUBKEY)
        manifest = build_manifest(content, "text/plain")
        with self.assertRaisesRegex(DropstitchError, "non-zero carrier padding"):
            decode_content(manifest, [script])

    def test_hash_mismatch_is_rejected(self) -> None:
        content = b"byte perfect"
        scripts = [
            build_script(item, PUBKEY, carrier_index=index)
            for index, item in enumerate(encode_payloads(content))
        ]
        manifest = bytearray(build_manifest(content, "text/plain"))
        manifest[16] ^= 1  # First SHA256 byte in the packed v1 header.
        with self.assertRaisesRegex(DropstitchError, "SHA256"):
            decode_content(bytes(manifest), scripts)

    def test_mixed_spend_keys_are_rejected(self) -> None:
        content = b"z" * (MAX_PAYLOAD_BYTES + 1)
        payloads = encode_payloads(content)
        scripts = [
            build_script(payloads[0], PUBKEY),
            build_script(payloads[1], OTHER_PUBKEY, carrier_index=1),
        ]
        with self.assertRaisesRegex(DropstitchError, "different spend key"):
            decode_content(build_manifest(content, "text/plain"), scripts)
        with self.assertRaisesRegex(DropstitchError, "expected key"):
            parse_script(scripts[0], expected_pubkey=OTHER_PUBKEY)

    def test_script_template_mutations_are_rejected(self) -> None:
        base = bytearray(build_script(b"payload", PUBKEY))
        mutations = []

        wrong_push = bytearray(base)
        wrong_push[0] = 0x4D  # OP_PUSHDATA2 is non-canonical here.
        mutations.append(wrong_push)

        wrong_drop = bytearray(base)
        first_drop = 2 * (2 + CHUNK_BYTES)
        wrong_drop[first_drop] = 0x75  # OP_DROP, not OP_2DROP.
        mutations.append(wrong_drop)

        no_auth = bytearray(base)
        no_auth[-1] = 0x51  # OP_TRUE cannot replace authenticated OP_CHECKSIG.
        mutations.append(no_auth)

        for number, malformed in enumerate(mutations):
            with self.subTest(mutation=number):
                with self.assertRaises(DropstitchError):
                    parse_script(bytes(malformed))

    def test_carrier_indices_domain_separate_repeated_payloads(self) -> None:
        payload = b"r" * MAX_PAYLOAD_BYTES
        scripts = [
            build_script(payload, PUBKEY, carrier_index=index)
            for index in range(2)
        ]
        self.assertNotEqual(scripts[0], scripts[1])
        self.assertNotEqual(
            p2wsh_scriptpubkey(scripts[0]), p2wsh_scriptpubkey(scripts[1])
        )
        content = payload * 2
        self.assertEqual(
            decode_content(build_manifest(content, "application/octet-stream"), scripts),
            content,
        )
        with self.assertRaisesRegex(DropstitchError, "non-canonical index"):
            decode_content(
                build_manifest(content, "application/octet-stream"),
                list(reversed(scripts)),
            )

    def test_canonical_witness_decoding_requires_sighash_all(self) -> None:
        content = b"signed framing"
        script = build_script(content, PUBKEY)
        manifest = build_manifest(content, "text/plain")
        self.assertEqual(
            decode_witnesses(
                manifest,
                [[CANONICAL_TEST_SIGNATURE, script]],
                expected_pubkey=PUBKEY,
            ),
            content,
        )

        wrong_sighash = CANONICAL_TEST_SIGNATURE[:-1] + b"\x02"
        with self.assertRaisesRegex(DropstitchError, "SIGHASH_ALL"):
            decode_witnesses(manifest, [[wrong_sighash, script]])
        with self.assertRaisesRegex(DropstitchError, "signature and script"):
            decode_witnesses(manifest, [[CANONICAL_TEST_SIGNATURE, b"extra", script]])

    def test_committed_decoder_requires_identical_funding_manifest(self) -> None:
        content = b"manifest commitment"
        script = build_script(content, PUBKEY)
        funding_manifest = build_manifest(content, "text/plain")
        witnesses = [[CANONICAL_TEST_SIGNATURE, script]]
        self.assertEqual(
            decode_committed_witnesses(
                funding_manifest,
                funding_manifest,
                witnesses,
                expected_pubkey=PUBKEY,
            ),
            content,
        )

        # The same padded script can describe this trailing-zero variant, but
        # the exact length and hash differ. The reveal cannot substitute even
        # another internally valid manifest for those identical padded bytes.
        substituted = build_manifest(content + b"\x00", "text/plain")
        self.assertEqual(
            build_script(content + b"\x00", PUBKEY),
            script,
        )
        with self.assertRaisesRegex(DropstitchError, "byte-identical"):
            decode_committed_witnesses(
                funding_manifest,
                substituted,
                witnesses,
                expected_pubkey=PUBKEY,
            )

    def test_signature_item_rejects_noncanonical_der_and_high_s(self) -> None:
        malformed = bytes.fromhex("30070202000102010101")
        with self.assertRaises(DropstitchError):
            validate_signature_item(malformed)

        high_s = (_SECP256K1_HALF_ORDER_FOR_TEST + 1).to_bytes(32, "big")
        high_s_signature = (
            b"\x30" + bytes((4 + 1 + len(high_s),))
            + b"\x02\x01\x01\x02" + bytes((len(high_s),)) + high_s + b"\x01"
        )
        with self.assertRaisesRegex(DropstitchError, "low-S"):
            validate_signature_item(high_s_signature)

    def test_invalid_public_keys_are_rejected(self) -> None:
        for pubkey in [b"", b"\x04" + b"\x00" * 32, b"\x02" + b"\xff" * 32]:
            with self.subTest(pubkey=pubkey.hex()):
                with self.assertRaises(DropstitchError):
                    build_script(b"x", pubkey)

    def test_bad_counts_and_empty_content_are_rejected(self) -> None:
        with self.assertRaises(DropstitchError):
            encode_payloads(b"")
        with self.assertRaisesRegex(DropstitchError, "carrier_index"):
            build_script(b"x", PUBKEY, carrier_index=1 << 32)
        with self.assertRaisesRegex(DropstitchError, "input_count"):
            build_manifest(b"x", "text/plain", input_count=2)
        with self.assertRaisesRegex(DropstitchError, "fewer inputs"):
            decode_content(build_manifest(b"x", "text/plain"), [])


if __name__ == "__main__":
    unittest.main()
