import base64
import importlib.util
import io
import json
import os
from pathlib import Path
import stat
import tempfile
import unittest
from unittest import mock


SCRIPT = Path(os.environ.get("KAIBA_OFFLINE_INVENTORY", str(
    Path(__file__).resolve().parents[2] / "scripts/offline-qualification/inventory.py")))
spec = importlib.util.spec_from_file_location("inventory", SCRIPT)
inventory = importlib.util.module_from_spec(spec)
spec.loader.exec_module(inventory)


def transcript(changes=None):
    values = {field: (1, b"") for field in inventory.FIELDS}
    values.update({
        "model": (0, b"Raspberry Pi 5 Model B Rev 1.1\0"),
        "architecture": (0, b"aarch64"),
        "kernel": (0, b"6.18.42"),
        "service_nginx": (0, b"active"),
        "service_spire-server": (3, b"inactive"),
        "ntp_synchronized": (0, b"yes"),
    })
    values.update(changes or {})
    return b"".join(name.encode() + b"|" + str(status).encode() + b"|" +
                    base64.b64encode(value) + b"\n"
                    for name, (status, value) in values.items())


class InventoryTest(unittest.TestCase):
    def project(self, raw):
        return inventory.project(raw, "mako", "2026-09-29T12:00:00Z", "sha256:" + "a" * 64)

    def test_observation_never_qualifies(self):
        report = self.project(transcript())
        self.assertEqual(report["observations"]["model"]["value"], "Raspberry Pi 5 Model B Rev 1.1")
        self.assertEqual(report["services"]["spire-server"]["value"], "inactive")
        self.assertEqual(report["observations"]["signed_boot_property"],
                         {"state": "not-observed", "exit_code": 1})
        for key in ("hardware_qualified", "offline_rollback_qualified", "boot_chain_authenticated",
                    "clock_continuity_qualified", "execution_authority", "publication_authorized"):
            self.assertIs(report[key], False)
        self.assertEqual(report["fleet_admission"], "unevaluated")

    def test_empty_success_does_not_establish_zero_or_false(self):
        report = self.project(transcript({"signed_boot_property": (0, b"")}))
        self.assertEqual(report["observations"]["signed_boot_property"]["state"], "not-observed")

    def test_failed_command_output_not_promoted(self):
        report = self.project(transcript({"bootloader_version": (1, b"untrusted failure text")}))
        self.assertNotIn("value", report["observations"]["bootloader_version"])
        self.assertNotIn("untrusted failure text", json.dumps(report))

    def test_service_command_failure_not_inactive(self):
        report = self.project(transcript({"service_spire-server": (127, b"inactive")}))
        self.assertEqual(report["services"]["spire-server"]["state"], "not-observed")

    def test_raw_digest_changes_with_evidence(self):
        first = self.project(transcript())
        second = self.project(transcript({"ntp_synchronized": (0, b"no")}))
        self.assertNotEqual(first["raw_evidence_sha256"], second["raw_evidence_sha256"])

    def test_incomplete_duplicate_unknown_and_trailing_records_rejected(self):
        raw = transcript()
        invalid = (b"\n".join(raw.splitlines()[1:]), raw + raw.splitlines()[0] + b"\n",
                   raw + b"otp_secret|0|YWJj\n", raw + b"unexpected\n")
        for value in invalid:
            with self.subTest(raw=value[-32:]), self.assertRaises(ValueError):
                self.project(value)

    def test_bad_encoding_status_and_bounds_rejected(self):
        invalid = (
            transcript({"kernel": (0, b"\x1b[31m")}),
            transcript({"kernel": (0, b"\xff")}),
            transcript({"kernel": (256, b"")}),
            transcript({"kernel": (0, b"x" * (inventory.MAX_FIELD + 1))}),
            transcript().replace(b"model|0|", b"model|00|", 1),
            transcript().replace(b"model|0|", b"model|0|!", 1),
            b"x" * (inventory.MAX_RAW + 1),
        )
        for value in invalid:
            with self.subTest(size=len(value)), self.assertRaises((ValueError, UnicodeError)):
                self.project(value)

    def test_only_known_hosts_and_strict_hostkey_verification(self):
        args = inventory.ssh_arguments("ace")
        self.assertIn("adam@ace.local", args)
        self.assertIn("StrictHostKeyChecking=yes", args)
        self.assertIn("UpdateHostKeys=no", args)
        self.assertIn("BatchMode=yes", args)
        self.assertIn("ClearAllForwardings=yes", args)
        with self.assertRaises(ValueError):
            inventory.ssh_arguments("mako; reboot")

    def fake_process(self, raw, returncode=0):
        process = mock.MagicMock()
        process.__enter__.return_value = process
        process.stdin = io.BytesIO()
        process.stdout = io.BytesIO(raw)
        process.wait.return_value = returncode
        return process

    def test_task_specific_hostkey_file_preserves_strict_verification(self):
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "known_hosts"
            path.write_text("test fixture key\n")
            args = inventory.ssh_arguments("ace", path)
            self.assertIn("UserKnownHostsFile=" + str(path), args)
            self.assertIn("StrictHostKeyChecking=yes", args)
            self.assertIn("GlobalKnownHostsFile=/dev/null", args)
            link = Path(temporary) / "link"
            link.symlink_to(path)
            for invalid in (link, Path(temporary), Path("relative"), Path("/tmp/a b")):
                with self.subTest(path=invalid), self.assertRaises(ValueError):
                    inventory.ssh_arguments("ace", invalid)

    def test_collection_retains_private_complete_raw_and_projection(self):
        raw = transcript()
        process = self.fake_process(raw)
        with tempfile.TemporaryDirectory() as temporary, mock.patch.object(
                inventory.subprocess, "Popen", return_value=process) as popen:
            output = Path(temporary) / "capture"
            report = inventory.collect("mako", output)
            self.assertEqual((output / "raw.txt").read_bytes(), raw)
            self.assertEqual((output / "collector.py").read_bytes(), SCRIPT.read_bytes())
            self.assertEqual(inventory.digest((output / "collector.py").read_bytes()), report["collector_sha256"])
            self.assertEqual(json.loads((output / "inventory.json").read_text()), report)
            self.assertEqual(stat.S_IMODE(output.stat().st_mode), 0o700)
            self.assertEqual(stat.S_IMODE((output / "raw.txt").stat().st_mode), 0o600)
            self.assertEqual(stat.S_IMODE((output / "inventory.json").stat().st_mode), 0o600)
            self.assertEqual(popen.call_args.args[0], inventory.ssh_arguments("mako"))
            with self.assertRaises(ValueError):
                inventory.collect("mako", output)

    def test_failed_ssh_or_incomplete_capture_cannot_create_report(self):
        for raw, code in ((transcript(), 255), (b"", 0), (transcript()[:20], 0)):
            with tempfile.TemporaryDirectory() as temporary, mock.patch.object(
                    inventory.subprocess, "Popen", return_value=self.fake_process(raw, code)):
                output = Path(temporary) / "capture"
                with self.assertRaises(ValueError):
                    inventory.collect("mako", output)
                self.assertFalse(output.exists())

    def test_private_collection_inside_checkout_rejected(self):
        with self.assertRaises(ValueError):
            inventory.collect("mako", SCRIPT.parent / "private-capture")


if __name__ == "__main__":
    unittest.main()
