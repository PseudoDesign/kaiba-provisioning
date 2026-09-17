import hashlib
import importlib.util
import json
from pathlib import Path
import tempfile
import re
import unittest
from unittest.mock import patch

SCRIPT = Path(__file__).resolve().parents[2] / ".github/scripts/device_secret_candidate.py"
SPEC = importlib.util.spec_from_file_location("device_secret_candidate", SCRIPT)
export = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(export)
REVISION = "a" * 40


class ExperimentExportTests(unittest.TestCase):
    def setUp(self):
        self.config = export.rehearsal_config(REVISION)

    def validate(self, value):
        raw = export.encoded(value)
        return export.validate_config(raw, REVISION, hashlib.sha256(raw).hexdigest())

    def test_configuration_and_exact_raw_digest(self):
        self.assertEqual(self.validate(self.config), self.config)
        raw = (json.dumps(self.config, indent=2) + "\n").encode()
        self.assertEqual(export.validate_config(raw, REVISION, hashlib.sha256(raw).hexdigest()), self.config)
        with self.assertRaisesRegex(ValueError, "digest mismatch"):
            export.validate_config(raw, REVISION, hashlib.sha256(raw.rstrip()).hexdigest())

    def test_rejects_source_substitution_secrets_paths_and_execution_flags(self):
        for name, value in (("source_revision", "b" * 40), ("schema_version", "another"),
                            ("scheme", "legacy-hkdf-v1"), ("private_key", "-----BEGIN PRIVATE KEY-----"),
                            ("host", "/dev/sda"), ("execution_authorized", True),
                            ("nonce_hex", "0" * 64), ("board_serial_sha256", "0123456789abcdef"),
                            ("disk_serial_sha256", "disk-serial"), ("slot_id", True),
                            ("slot_id", 2), ("expected_usage", False), ("expected_usage", 1),
                            ("partition_uuid", self.config["volume_uuid"]),
                            ("volume_uuid", "00000000-0000-0000-0000-000000000000"),
                            ("experiment_id", '${builtins.readFile "/secret"}'),
                            ("target_reference", "a\n::warning::injected")):
            with self.subTest(name=name, value=value), self.assertRaises(ValueError):
                self.validate({**self.config, name: value})
        for usage in (0, 8, 9, 10, 11, 12, 13, 14):
            self.validate({**self.config, "expected_usage": usage})

    def test_rejects_duplicate_nonfinite_oversized_and_missing_fields(self):
        raw = export.encoded(self.config)
        for bad in (raw.replace(b'"slot_id":1', b'"slot_id":1,"slot_id":1'),
                    raw.replace(b'"slot_id":1', b'"slot_id":NaN'),
                    raw + b' ' * export.LIMIT, b'[]', b'{}'):
            with self.subTest(data=bad[:40]), self.assertRaises(ValueError):
                export.validate_config(bad, REVISION, hashlib.sha256(bad).hexdigest())

    def test_expression_pins_source_native_system_and_all_five_outputs(self):
        expr = export.expression('git+file:///tmp/${injection}?rev=' + REVISION,
                                 REVISION, 1786968000, self.config)
        self.assertIn(r'\${injection}', expr)
        self.assertIn('assert f.rev == "' + REVISION + '"', expr)
        self.assertIn('assert builtins.currentSystem == "aarch64-linux"', expr)
        self.assertIn('assert s.system == "aarch64-linux"', expr)
        for role in ("unsigned", "signing_plan", "signing_input", "review", "checked_config"):
            self.assertIn(role + " = ", expr)
        self.assertNotIn("author", expr)
        self.assertNotIn("run-reviewed-experiment", expr)

    def test_native_guard_rejects_emulated_x86_host(self):
        with patch.object(export.candidate.platform, "machine", return_value="x86_64"), \
                patch.object(export.candidate.platform, "system", return_value="Linux"), \
                patch.object(export.candidate, "run") as run:
            with self.assertRaisesRegex(ValueError, "native aarch64"):
                export.candidate.require_native_system(export.SYSTEM)
            run.assert_not_called()

    def test_output_cross_bindings_and_substituted_artifacts(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            outputs = {key: str(root / key) for key in
                       ("unsigned", "signing_plan", "signing_input", "review", "checked_config")}
            for directory in outputs.values():
                Path(directory).mkdir()
            def write(role, name, value):
                path = Path(outputs[role]) / name
                path.parent.mkdir(parents=True, exist_ok=True)
                raw = value if isinstance(value, bytes) else export.encoded(value)
                path.write_bytes(raw)
                return "sha256:" + hashlib.sha256(raw).hexdigest()
            files = {}
            artifacts = {}
            for role, name, data in (("boot_image", "unsigned/boot.img", b"boot"),
                                     ("root_data", "nvme/root-data.img", b"root"),
                                     ("root_hash_tree", "nvme/root-hash.img", b"tree")):
                digest = write("unsigned", name, data)
                if role == "boot_image":
                    path = Path(outputs["unsigned"]) / name
                    with path.open("wb") as stream:
                        stream.truncate(96 * 1024 * 1024)
                    digest = "sha256:" + export.candidate.file_sha256(path)
                files[role] = {"digest": digest, "size_bytes": (Path(outputs["unsigned"]) / name).stat().st_size}
                artifacts[role] = {"path": name, "digest": digest}
            with (Path(outputs["signing_plan"]) / "boot.img").open("wb") as stream:
                stream.truncate(96 * 1024 * 1024)
            unsigned = {"source_revision": REVISION, "signing_status": "unsigned", "artifacts": artifacts}
            unsigned_hash = write("unsigned", "manifest.json", unsigned)
            config_hash = write("checked_config", "experiment.json", self.config)
            write("review", "experiment.json", self.config)
            review = {"source_revision": REVISION, "signing_status": "unsigned", "hardware_observed": False,
                      "fleet_admission": "unevaluated", "device_secret_experiment_digest": config_hash,
                      "device_secret_execution": "pending-separate-authority"}
            review_hash = write("review", "review.json", review)
            manifest = {"source_revision": REVISION, "review_digest": review_hash,
                        "unsigned_artifacts_digest": unsigned_hash, "hardware_observed": False,
                        "fleet_admission": "unevaluated", **files}
            manifest_hash = write("signing_input", "manifest.json", manifest)
            intent = {"source_revision": REVISION, "source_date_epoch": 1,
                      "authorization_scope": "native_offline_boot", "unsigned_manifest_digest": manifest_hash,
                      "signing_input": {"role": "rpi5.boot_image", **files["boot_image"]}}
            write("signing_plan", "release-intent.json", intent)
            write("signing_plan", "plan.json", {"source_date_epoch": 1})
            # Regular sparse fixtures exercise byte bindings without a device.
            # The actual Nix build and closure export run in the native CI rehearsal.
            with patch.object(export, "STORE", re.escape(temporary) + r"/[a-z_]+"):
                export.validate_outputs(outputs, self.config, REVISION, 1)
                with (Path(outputs["signing_plan"]) / "boot.img").open("r+b") as stream:
                    stream.write(b"substituted")
                with self.assertRaisesRegex(ValueError, "exact experiment image"):
                    export.validate_outputs(outputs, self.config, REVISION, 1)
                write("unsigned", "nvme/root-data.img", b"substituted")
                with self.assertRaisesRegex(ValueError, "artifact bytes"):
                    export.validate_outputs(outputs, self.config, REVISION, 1)
                write("review", "experiment.json", {**self.config, "nonce_hex": "e" * 64})
                with self.assertRaisesRegex(ValueError, "checked experiment"):
                    export.validate_outputs(outputs, self.config, REVISION, 1)
                write("review", "experiment.json", self.config)
                write("review", "review.json", {**review, "device_secret_execution": "authorized"})
                with self.assertRaisesRegex(ValueError, "without execution authority"):
                    export.validate_outputs(outputs, self.config, REVISION, 1)


if __name__ == "__main__":
    unittest.main()
