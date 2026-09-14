import importlib.util
import io
import json
import os
from pathlib import Path
import struct
import tempfile
import unittest
from unittest import mock


spec = importlib.util.spec_from_file_location("gpt_capture", Path(__file__).with_name("capture.py"))
capture = importlib.util.module_from_spec(spec)
spec.loader.exec_module(capture)


class CaptureTests(unittest.TestCase):
    def source(self, alternate=999):
        source = tempfile.TemporaryFile()
        self.addCleanup(source.close)
        source.truncate(1000 * 512)
        primary = bytearray(512)
        primary[:8] = b"EFI PART"
        struct.pack_into("<Q", primary, 32, alternate)
        source.seek(512)
        source.write(primary)
        source.flush()
        return source

    def test_canonical_capture_is_bounded_and_source_unchanged(self):
        source = self.source()
        before = os.pread(source.fileno(), 1000 * 512, 0)
        result = capture.capture(source.fileno(), "synthetic test image")
        self.assertEqual(result["source_kind"], "image-file")
        self.assertEqual([r["offset_bytes"] for r in result["regions"]], [0, 967 * 512])
        self.assertEqual(sum(len(capture.base64.b64decode(r["data_base64"])) for r in result["regions"]), 67 * 512)
        self.assertEqual(os.pread(source.fileno(), 1000 * 512, 0), before)

    def test_image_sized_gpt_retains_both_backup_locations(self):
        source = self.source(alternate=499)
        result = capture.capture(source.fileno(), "synthetic image-sized GPT")
        self.assertEqual([r["offset_bytes"] for r in result["regions"]], [0, 467 * 512, 967 * 512])
        self.assertEqual(sum(len(capture.base64.b64decode(r["data_base64"])) for r in result["regions"]), 100 * 512)

    def test_checked_reconstruction_roundtrips_exact_metadata(self):
        repository = Path(__file__).resolve().parents[3]
        fixture = json.loads((repository / "internal/provisioning/campaignmedia/testdata/gpt-captures/reconstructed-aligned-nvme.capture.json").read_text())
        with tempfile.TemporaryFile() as source:
            # Only 34 KiB are written; all other apparent image bytes are holes.
            source.truncate(fixture["capacity_bytes"])
            for region in fixture["regions"]:
                source.seek(region["offset_bytes"])
                source.write(capture.base64.b64decode(region["data_base64"]))
            source.flush()
            result = capture.capture(source.fileno(), "round trip of a synthetic reconstruction")
        self.assertEqual(result["regions"], fixture["regions"])
        self.assertEqual(result["capacity_bytes"], fixture["capacity_bytes"])
        self.assertEqual(result["source_kind"], "image-file")

    def test_corrupt_alternate_cannot_trigger_out_of_bounds_read(self):
        source = self.source(alternate=2**64 - 1)
        with self.assertRaisesRegex(ValueError, "capture bounds"):
            capture.capture(source.fileno(), "invalid GPT")

    def test_changed_metadata_rejected(self):
        source = self.source()
        original = capture.read_exact
        reads = 0

        def read(fd, offset, size):
            nonlocal reads
            reads += 1
            data = original(fd, offset, size)
            return bytes([data[0] ^ 1]) + data[1:] if reads == 4 else data

        with mock.patch.object(capture, "read_exact", side_effect=read):
            with self.assertRaisesRegex(ValueError, "changed between read passes"):
                capture.capture(source.fileno(), "changing GPT")

    def test_cli_opens_read_only(self):
        source = self.source()
        with mock.patch.object(capture.sys, "argv", ["capture.py", "--source", "/fixture", "--description", "test"]):
            with mock.patch.object(capture.os, "open", return_value=os.dup(source.fileno())) as opened:
                with mock.patch.object(capture.sys, "stdout", io.StringIO()):
                    capture.main()
        self.assertEqual(opened.call_args.args[1] & os.O_ACCMODE, os.O_RDONLY)


if __name__ == "__main__":
    unittest.main()
