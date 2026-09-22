import copy
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

spec = importlib.util.spec_from_file_location("assessor", os.environ["KAIBA_COMPARISON_ASSESSOR"])
assessor = importlib.util.module_from_spec(spec)
spec.loader.exec_module(assessor)


def fixture():
    common = {"image_sha256": "a" * 64, "source_boot_image_sha256": "b" * 64,
              "source_verity_root_hash": "c" * 64, "volume_uuid": "11111111-1111-4111-8111-111111111111",
              "nonce_hex": "d" * 64, "challenge_hex": "e" * 64, "firmware_version": "f" * 40}
    board = {"board_serial_sha256": "1" * 64, "kernel_release": "test-kernel",
             "boot_id": "22222222-2222-4222-8222-222222222222", "expected_usage": 8}
    second = board | {"board_serial_sha256": "2" * 64}
    plan = common | {"schema_version": "kaiba.copied-storage-assessment/v1alpha1", "original": board, "comparison": second}
    result = {key: False for key in assessor.BOOLS} | {key: 0 for key in assessor.INTS} | common
    result.update(schema_version="kaiba.copied-storage-result/v1alpha1", mode="development", stop="complete",
                  passed=True, local_control_verified=True, runtime_locks_closed=True,
                  storage_closed=True, image_unchanged=True, last_mailbox_tag=0x30092)
    key = Ed25519PrivateKey.generate()
    original = result | board | {"role": "original", "source_key_accepted": True, "source_unlocked": True, "source_record_verified": True,
        "fixture_public_key_hex": key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw).hex(),
        "fixture_signature_hex": key.sign(bytes.fromhex(common["challenge_hex"])).hex()}
    comparison = result | second | {"role": "comparison", "copied_fixture_rejected": True,
        "source_unlock_return_code": -1, "fixture_public_key_hex": "", "fixture_signature_hex": ""}
    return plan, original, comparison


class AssessmentTests(unittest.TestCase):
    def test_verified_pair(self):
        result = assessor.assess(*fixture())
        self.assertEqual(result["status"], "matched-development-comparison")
        self.assertFalse(result["hardware_qualified"])
        self.assertFalse(result["fleet_identity_qualified"])

    def test_missing_controls_cleanup_and_typed_results(self):
        for which in [1, 2]:
            for field in ["passed", "local_control_verified", "runtime_locks_closed", "storage_closed", "image_unchanged"]:
                for value in [False, 1, "true"]:
                    with self.subTest(which=which, field=field, value=value):
                        values = fixture(); values[which][field] = value
                        with self.assertRaises(ValueError): assessor.assess(*values)

    def test_rejects_wrong_pair_and_unsupported_failures(self):
        for field, value in [("mode", "synthetic-development"), ("source_unlock_return_code", -5),
                             ("source_unlocked", True), ("copied_fixture_rejected", False),
                             ("hardware_qualified", True), ("image_sha256", "3" * 64),
                             ("last_mailbox_errno", 22), ("fixture_signature_hex", "1" * 128)]:
            values = fixture(); values[2][field] = value
            with self.subTest(field=field), self.assertRaises(ValueError): assessor.assess(*values)

    def test_signature_verification_is_cryptographic(self):
        for field in ["fixture_public_key_hex", "fixture_signature_hex", "challenge_hex"]:
            values = fixture(); values[1][field] = "1" * len(values[1][field])
            with self.subTest(field=field), self.assertRaises(Exception): assessor.assess(*values)

    def test_plan_and_result_fields_are_closed(self):
        for which in range(3):
            values = fixture(); values[which]["unexpected"] = True
            with self.assertRaises(ValueError): assessor.assess(*values)
        values = fixture(); values[0]["comparison"] = copy.deepcopy(values[0]["original"])
        values[2].update(values[0]["comparison"])
        with self.assertRaises(ValueError): assessor.assess(*values)

    def test_duplicate_json_rejected(self):
        with self.assertRaises(ValueError):
            json.loads('{"passed":true,"passed":false}', object_pairs_hook=assessor.closed_object)


class ConfigTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(); self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        plan, _, _ = fixture()
        self.request = {key: value for key, value in plan.items() if key not in ["original", "comparison", "volume_uuid", "nonce_hex"]}
        self.request.update(schema_version="kaiba.copied-storage-comparison/v1alpha1", role="original",
                            board_serial_sha256="1" * 64, kernel_release="test-kernel", expected_usage=8,
                            scheme="kaiba-firmware-hmac-counter-v1")
        self.source = dict(schema_version="kaiba.device-secret-storage-offline-development/v1alpha1",
            scheme="kaiba-firmware-hmac-counter-v1", experiment_id="comparison-test", target_reference="original-test",
            source_revision="1" * 40, volume_uuid=plan["volume_uuid"], partition_uuid="33333333-3333-4333-8333-333333333333",
            board_serial_sha256="1" * 64, disk_serial_sha256="2" * 64, nonce_hex=plan["nonce_hex"], slot_id=1, expected_usage=8)

    def run_config(self, passed):
        config = self.root / "config.json"; source = self.root / "source.json"
        config.write_text(json.dumps(self.request)); source.write_text(json.dumps(self.source))
        result = subprocess.run([os.environ["KAIBA_COMPARISON_HELPER"], "--check-config", str(config), str(source)], capture_output=True, text=True)
        self.assertEqual(result.returncode == 0, passed, result.stdout + result.stderr)

    def test_valid_original_and_comparison(self):
        self.run_config(True)
        self.request.update(role="comparison", board_serial_sha256="3" * 64)
        self.run_config(True)

    def test_wrong_board_roles_reject(self):
        self.request["role"] = "comparison"; self.run_config(False)
        self.request.update(role="original", board_serial_sha256="3" * 64); self.run_config(False)

    def test_malformed_bindings_and_sources_reject(self):
        saved = copy.deepcopy(self.request)
        for field, value in [("image_sha256", "0" * 64), ("challenge_hex", "ab"),
                             ("expected_usage", True), ("role", "retry"), ("unexpected", 1)]:
            self.request = saved | {field: value}; self.run_config(False)
        self.request = saved; self.source["schema_version"] = "kaiba.device-secret-target/v1alpha1"
        self.run_config(False)


if __name__ == "__main__": unittest.main()
