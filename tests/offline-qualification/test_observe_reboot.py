import base64
import copy
import importlib.util
import io
import json
import os
from pathlib import Path
import stat
import tempfile
import unittest
from unittest import mock


SCRIPT = Path(os.environ.get("KAIBA_REBOOT_OBSERVER", str(
    Path(__file__).resolve().parents[2] / "scripts/offline-qualification/observe_reboot.py")))
spec = importlib.util.spec_from_file_location("observe_reboot", SCRIPT)
observer = importlib.util.module_from_spec(spec)
spec.loader.exec_module(observer)
SYSTEM = "/nix/store/" + "a" * 32 + "-nixos-system-ace-26.05.example"
OLD_SYSTEM = SYSTEM.replace("a" * 32, "b" * 32)
SPIFFE_ID = "spiffe://pilot.kaiba.pseudo.design/device/ace/instance/ace-pilot-20260929/workload/identity-probe"
BEFORE = "2026-09-29T08:00:00Z"
AFTER = "2026-09-29T08:02:00Z"


def transcript(post=False, changes=None):
    at = AFTER if post else BEFORE
    uptime = 90 if post else 10000
    unit = {"InvocationID": ("c" if post else "b") * 32,
            "ExecMainStartTimestampMonotonic": str((uptime - 12) * 1_000_000),
            "ExecMainExitTimestampMonotonic": str((uptime - 10) * 1_000_000),
            "ExecMainStatus": "0", "Result": "success", "ActiveState": "inactive"}
    unit_raw = "\n".join(k + "=" + v for k, v in unit.items())
    probe = json.dumps({"spiffe_id": SPIFFE_ID, "serial": "42", "not_after": "2026-09-29T09:00:00Z", "pid": 123})
    probe_stat = str(int(observer.timestamp(at)) - 11) + ":" + str(len(probe)) + ":42"
    values = {name: (0, "") for name in observer.FIELDS}
    values.update({
        "boot_id": (0, "00000000-0000-0000-0000-00000000000" + ("2" if post else "1")),
        "current_system": (0, SYSTEM), "persistent_system": (0, SYSTEM),
        "booted_system": (0, SYSTEM if post else OLD_SYSTEM), "generation": (0, "system-10-link"),
        "bundle_digest": (0, "a" * 64 + "  /var/lib/kaiba/identity/pilot-bootstrap/trust-bundle.pem"),
        "probe_unit_before": (0, unit_raw), "probe_unit_after": (0, unit_raw), "probe": (0, probe),
        "probe_stat_before": (0, probe_stat), "probe_stat_after": (0, probe_stat),
        "enrollment": (0, json.dumps({"schema_version": "kaiba.pilot-device-client/v1alpha1", "phase": "verified",
                                      "spki_digest": "public-digest", "spki": "public-key-not-to-export",
                                      "enrollment_id": "private-public-status-id", "logical_device_id": "device-1",
                                      "renewal": {"credential_revision": 3}})),
        "pilot_directory": (0, "994:988:700"), "pilot_file": (0, "994:988:600:1"),
        "pilot_mount": (0, "rw,nosuid,nodev,noexec,relatime"), "ntp": (0, "yes"),
        "uptime": (0, f"{uptime}.00 100.00"), "target_utc": (0, at),
    })
    for service in observer.SERVICES:
        values["service_" + service] = (0, "active")
    values["boot_id_end"] = values["boot_id"]
    values.update(changes or {})
    return b"".join(name.encode() + b"|" + str(code).encode() + b"|" + base64.b64encode(value.encode()) + b"\n"
                    for name, (code, value) in values.items())


class RebootObserverTest(unittest.TestCase):
    def observations(self):
        return observer.project(transcript(), BEFORE), observer.project(transcript(True), AFTER)

    def compare(self, before, after, **kwargs):
        return observer.compare(before, after, SYSTEM, 10, SPIFFE_ID, **kwargs)

    def test_valid_warm_reboot_observation_does_not_promote_qualification(self):
        before, after = self.observations()
        self.assertTrue(before["ready_for_comparison"])
        result = self.compare(before, after)
        self.assertTrue(result["warm_reboot_observation_passed"])
        for key in ("physical_cold_boot_tested", "hardware_qualified", "boot_chain_authenticated",
                    "offline_rollback_qualified", "clock_continuity_qualified", "dns_publication_tested",
                    "reboot_action_independently_verified", "publication_authorized"):
            self.assertIs(result[key], False)
        self.assertEqual(result["fleet_admission"], "unevaluated")

    def test_same_boot_stale_or_wrong_profile_cannot_pass(self):
        before, after = self.observations()
        mutations = {
            "boot_id": before["boot_id"], "probe_invocation_id": before["probe_invocation_id"],
            "current_system": OLD_SYSTEM, "persistent_system": OLD_SYSTEM, "booted_system": OLD_SYSTEM,
            "system_generation": 11, "spiffe_id": SPIFFE_ID.replace("ace-pilot", "other-pilot"),
            "trust_bundle_sha256": "sha256:" + "b" * 64, "public_enrollment_sha256": "sha256:" + "b" * 64,
            "uptime_seconds": 10000, "ready_for_comparison": False,
            "collected_at_station_utc": "2026-09-29T09:00:00Z",
        }
        for field, value in mutations.items():
            with self.subTest(field=field):
                changed = {**after, field: value}
                self.assertFalse(self.compare(before, changed)["warm_reboot_observation_passed"])
        self.assertFalse(self.compare(after, before)["warm_reboot_observation_passed"])

    def test_current_boot_probe_freshness_is_required(self):
        raw = transcript(True)
        fields = observer.parse(raw)
        base_unit = fields["probe_unit_before"][1]
        variants = [
            base_unit.replace("InvocationID=" + "c" * 32, "InvocationID="),
            base_unit.replace("ExecMainStartTimestampMonotonic=78000000", "ExecMainStartTimestampMonotonic=0"),
            base_unit.replace("ExecMainExitTimestampMonotonic=80000000", "ExecMainExitTimestampMonotonic=999000000"),
            base_unit.replace("Result=success", "Result=exit-code"),
            base_unit.replace("ExecMainStatus=0", "ExecMainStatus=1"),
            base_unit.replace("ActiveState=inactive", "ActiveState=activating"),
        ]
        for unit in variants:
            with self.subTest(unit=unit):
                report = observer.project(transcript(True, {"probe_unit_before": (0, unit), "probe_unit_after": (0, unit)}), AFTER)
                self.assertFalse(report["ready_for_comparison"])
        old_stat = "1:100:42"
        report = observer.project(transcript(True, {"probe_stat_before": (0, old_stat), "probe_stat_after": (0, old_stat)}), AFTER)
        self.assertIn("probe-output-not-from-invocation", report["readiness_issues"])
        # A recent file cannot rescue a unit whose last completed run is old.
        old_unit = base_unit.replace("78000000", "1000000").replace("80000000", "2000000")
        report = observer.project(transcript(False, {"probe_unit_before": (0, old_unit), "probe_unit_after": (0, old_unit)}), BEFORE)
        self.assertIn("probe-not-fresh-in-current-boot", report["readiness_issues"])

    def test_expired_identity_unsynced_time_and_service_failures_not_ready(self):
        probe = observer.strict_json(observer.parse(transcript())["probe"][1])
        probe["not_after"] = BEFORE
        cases = ({"probe": (0, json.dumps(probe))}, {"ntp": (0, "no")},
                 {"failed_units": (0, "failed.service loaded failed failed")},
                 {"service_hydra-server": (3, "inactive")}, {"grant_absent": (1, "")},
                 {"pilot_file": (0, "994:988:644:1")}, {"pilot_mount": (0, "rw,nosuid,nodev")},
                 {"target_utc": (0, "2026-09-29T07:59:00Z")})
        for changes in cases:
            with self.subTest(changes=changes):
                self.assertFalse(observer.project(transcript(changes=changes), BEFORE)["ready_for_comparison"])

    def test_partial_ambiguous_or_racing_evidence_rejected(self):
        raw = transcript()
        invalid = [b"\n".join(raw.splitlines()[1:]), raw + raw.splitlines()[0] + b"\n",
                   raw + b"private_key|0|YWJj\n", b"x" * (observer.MAX_RAW + 1),
                   transcript(changes={"boot_id_end": (0, "00000000-0000-0000-0000-000000000099")}),
                   transcript(changes={"probe_stat_after": (0, "100:20:30")}),
                   transcript(changes={"probe": (0, '{"spiffe_id":"one","spiffe_id":"two"}')}),
                   transcript(changes={"enrollment": (0, '{"schema_version":"x","schema_version":"y"}')}),
                   transcript(changes={"bundle_digest": (1, "")}),
                   transcript(changes={"probe": (0, "x" * (observer.MAX_FIELD + 1))})]
        for candidate in invalid:
            with self.subTest(length=len(candidate)), self.assertRaises(ValueError):
                observer.project(candidate, BEFORE)

    def test_public_projection_contains_hash_only_for_enrollment(self):
        before, _ = self.observations()
        serialized = json.dumps(before)
        self.assertNotIn("private-public-status-id", serialized)
        self.assertNotIn("public-key-not-to-export", serialized)
        self.assertNotIn("credential_revision", serialized)
        status = observer.strict_json(observer.parse(transcript())["enrollment"][1])
        status["renewal"]["credential_revision"] += 1
        changed = observer.project(transcript(changes={"enrollment": (0, json.dumps(status))}), BEFORE)
        self.assertNotEqual(before["public_enrollment_sha256"], changed["public_enrollment_sha256"])

    def test_private_capture_reprojects_and_detects_report_or_source_edits(self):
        raw = transcript()
        report = observer.project(raw, BEFORE)
        with tempfile.TemporaryDirectory() as temporary:
            capture = Path(temporary) / "before"
            observer.private_write(capture, {"raw.txt": raw, "observation.json": observer.encode(report),
                                            "observe_reboot.py": SCRIPT.read_bytes(),
                                            "inventory.py": observer.INVENTORY.read_bytes()})
            self.assertEqual(observer.read_capture(capture), report)
            self.assertEqual(stat.S_IMODE(capture.stat().st_mode), 0o700)
            self.assertEqual(stat.S_IMODE((capture / "raw.txt").stat().st_mode), 0o600)
            modified = {**report, "system_generation": 99}
            (capture / "observation.json").write_bytes(observer.encode(modified))
            with self.assertRaisesRegex(ValueError, "projection-mismatch"):
                observer.read_capture(capture)
            (capture / "observation.json").write_bytes(observer.encode(report))
            (capture / "observe_reboot.py").write_text("different collector")
            with self.assertRaisesRegex(ValueError, "version-mismatch"):
                observer.read_capture(capture)

    def test_transport_is_strict_and_has_no_remote_mutation(self):
        process = mock.MagicMock()
        process.__enter__.return_value = process
        process.stdin = io.BytesIO()
        process.stdout = io.BytesIO(transcript())
        process.wait.return_value = 0
        with tempfile.TemporaryDirectory() as temporary, mock.patch.object(observer.subprocess, "Popen", return_value=process) as popen:
            output = Path(temporary) / "capture"
            # Local current time is irrelevant to testing the transport. A
            # mismatched clock is retained as unready rather than accepted.
            observer.collect(output, None)
            args = popen.call_args.args[0]
            for expected in ("StrictHostKeyChecking=yes", "UpdateHostKeys=no", "ControlMaster=no", "ControlPath=none", "ClearAllForwardings=yes"):
                self.assertIn(expected, args)
            self.assertEqual(args[-4:], ["sudo", "-n", "sh", "-s"])
            for forbidden in ("systemctl start", "systemctl restart", "systemctl reboot", "spire-server agent", "keys.json", "manifest.json"):
                self.assertNotIn(forbidden, observer.REMOTE_SCRIPT)
            with self.assertRaises(ValueError):
                observer.collect(output, None)


if __name__ == "__main__":
    unittest.main()
