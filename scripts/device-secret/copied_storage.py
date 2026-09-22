#!/usr/bin/env python3
"""File-only assessment of an exact original/comparison pair. No hardware I/O."""
import argparse
import json
import re
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey


def require(condition, message):
    if not condition:
        raise ValueError(message)


def closed_object(pairs):
    result = {}
    for key, value in pairs:
        require(key not in result, "duplicate JSON key")
        result[key] = value
    return result


def read(path):
    with Path(path).open("rb") as stream:
        data = stream.read(16385)
    require(len(data) <= 16384, "oversized input")
    return json.loads(data, object_pairs_hook=closed_object)


COMMON = {
    "image_sha256", "source_boot_image_sha256", "source_verity_root_hash",
    "volume_uuid", "nonce_hex", "challenge_hex", "firmware_version",
}
BOARD = {"board_serial_sha256", "kernel_release", "boot_id", "expected_usage"}
BOOLS = {
    "passed", "local_control_verified", "source_key_accepted", "source_unlocked", "source_record_verified",
    "copied_fixture_rejected", "runtime_locks_closed", "storage_closed", "image_unchanged",
    "hardware_qualified", "fleet_identity_qualified", "lock_rejection_qualified",
}
INTS = {"source_unlock_return_code", "last_firmware_outcome", "last_mailbox_tag", "last_mailbox_errno"}
FIELDS = COMMON | BOARD | BOOLS | INTS | {
    "schema_version", "mode", "role", "stop", "fixture_public_key_hex", "fixture_signature_hex",
}


def hexadecimal(value, length):
    return isinstance(value, str) and re.fullmatch(r"[0-9a-f]{" + str(length) + "}", value) and int(value, 16) != 0


def uuid(value):
    return isinstance(value, str) and re.fullmatch(r"[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}", value) and value != "00000000-0000-0000-0000-000000000000"


def assess(plan, original, comparison):
    require(isinstance(plan, dict) and set(plan) == COMMON | {"schema_version", "original", "comparison"}, "invalid plan fields")
    require(plan["schema_version"] == "kaiba.copied-storage-assessment/v1alpha1", "invalid plan schema")
    for key in COMMON - {"volume_uuid"}:
        require(hexadecimal(plan[key], 40 if key == "firmware_version" else 64), "invalid plan digest")
    require(uuid(plan["volume_uuid"]), "invalid volume UUID")
    for role, result in [("original", original), ("comparison", comparison)]:
        binding = plan[role]
        require(isinstance(binding, dict) and set(binding) == BOARD, "invalid board binding")
        require(hexadecimal(binding["board_serial_sha256"], 64) and uuid(binding["boot_id"]), "invalid board identity")
        require(isinstance(binding["kernel_release"], str) and 0 < len(binding["kernel_release"]) <= 128, "invalid kernel")
        require(type(binding["expected_usage"]) is int and binding["expected_usage"] in [0, *range(8, 15)], "invalid usage")
        require(isinstance(result, dict) and set(result) == FIELDS, "invalid result fields")
        require(result["schema_version"] == "kaiba.copied-storage-result/v1alpha1" and result["mode"] == "development", "invalid or synthetic result")
        require(result["role"] == role and result["stop"] == "complete", "wrong role or failed result")
        for key in COMMON:
            require(result[key] == plan[key], "changed shared binding: " + key)
        for key in BOARD:
            require(type(result[key]) is type(binding[key]) and result[key] == binding[key], "changed board binding: " + key)
        require(all(type(result[k]) is bool for k in BOOLS) and all(type(result[k]) is int for k in INTS), "invalid result types")
        require(all(result[k] for k in ["passed", "local_control_verified", "runtime_locks_closed", "storage_closed", "image_unchanged"]), "missing control or cleanup")
        require(not any(result[k] for k in ["hardware_qualified", "fleet_identity_qualified", "lock_rejection_qualified"]), "overstated qualification")
        require((result["last_firmware_outcome"], result["last_mailbox_tag"], result["last_mailbox_errno"]) == (0, 0x30092, 0), "failed firmware derivation")
    require(plan["original"]["board_serial_sha256"] != plan["comparison"]["board_serial_sha256"], "same board")
    require(original["source_key_accepted"] and original["source_unlocked"] and original["source_record_verified"] and not original["copied_fixture_rejected"] and original["source_unlock_return_code"] == 0, "missing original control")
    require(not comparison["source_key_accepted"] and not comparison["source_unlocked"] and not comparison["source_record_verified"] and comparison["copied_fixture_rejected"] and comparison["source_unlock_return_code"] == -1, "not an exact wrong-key rejection")
    require(comparison["fixture_public_key_hex"] == comparison["fixture_signature_hex"] == "", "unexpected comparison identity")
    require(hexadecimal(original["fixture_public_key_hex"], 64) and hexadecimal(original["fixture_signature_hex"], 128), "invalid fixture proof")
    Ed25519PublicKey.from_public_bytes(bytes.fromhex(original["fixture_public_key_hex"])).verify(
        bytes.fromhex(original["fixture_signature_hex"]), bytes.fromhex(plan["challenge_hex"]))
    return {
        "status": "matched-development-comparison", "image_sha256": plan["image_sha256"],
        "original_record_authenticated": True, "local_controls_verified": True,
        "copied_fixture_rejected": True, "original_fixture_identity_proof_verified": True,
        "comparison_fixture_identity_unavailable": True,
        "hardware_qualified": False, "fleet_identity_qualified": False,
        "lock_rejection_qualified": False, "execution_authority": False,
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for field in ["plan", "original", "comparison"]:
        parser.add_argument("--" + field, required=True)
    args = parser.parse_args()
    try:
        value = assess(read(args.plan), read(args.original), read(args.comparison))
    except Exception as error:
        parser.exit(1, "comparison rejected: " + type(error).__name__ + ": " + str(error) + "\n")
    print(json.dumps(value, sort_keys=True))


if __name__ == "__main__":
    main()
