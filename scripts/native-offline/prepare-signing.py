#!/usr/bin/env python3
"""Build public signing inputs from store-backed native candidate bytes."""
import hashlib
import json
import pathlib
import subprocess
import sys
import tempfile


def digest(path):
    with path.open("rb") as stream:
        return "sha256:" + hashlib.file_digest(stream, "sha256").hexdigest()


def encoded(value):
    return json.dumps(value, separators=(",", ":")).encode()


def write(path, value):
    path.write_bytes(encoded(value) + b"\n")


def require(condition, message):
    if not condition:
        raise ValueError(message)


def main():
    unsigned, review, key, signer_review, output, inputs = map(pathlib.Path, sys.argv[1:7])
    source, epoch = sys.argv[7:9]
    epoch = int(epoch)
    m = json.loads((unsigned / "manifest.json").read_bytes())
    r = json.loads((review / "review.json").read_bytes())
    public = json.loads(signer_review.read_bytes())["public_bindings"]
    require(m["source_revision"] == r["source_revision"] == source, "source mismatch")
    require(r["artifact_bundle_digest"] == m["bundle_digest"], "review bundle mismatch")
    require(r["signing_status"] == m["signing_status"] == "unsigned", "expected unsigned candidate")
    require(r["hardware_observed"] is False and r["fleet_admission"] == "unevaluated", "unexpected qualification claim")
    require(r["normal_boot_medium"] == r["system_root_medium"] == "nvme", "wrong topology")
    require(m["expected_customer_key_hash"] == public["customer_key_hash"], "customer key mismatch")
    require(digest(key) == "sha256:" + public["public_key_file_sha256"], "public key mismatch")
    der = subprocess.check_output(["openssl", "pkey", "-pubin", "-in", str(key), "-outform", "DER"])
    require("sha256:" + hashlib.sha256(der).hexdigest() == public["public_key_fingerprint"], "fingerprint mismatch")
    with tempfile.TemporaryDirectory() as temporary:
        customer_key = pathlib.Path(temporary) / "customer-key.bin"
        subprocess.run([sys.executable, sys.argv[9], str(key), "--output", str(customer_key)], check=True)
        require(customer_key.stat().st_size == 264 and digest(customer_key) == public["customer_key_hash"], "Raspberry Pi customer-key encoding mismatch")
    data_guid = "b1a02b6c-8ec1-4ca9-9b8a-348211271de0"
    hash_guid = "66d98f80-4260-4de0-98b5-232bcac98e29"
    require(m["verity"]["data_device"] == "PARTUUID=" + data_guid, "data selector mismatch")
    require(m["verity"]["hash_device"] == "PARTUUID=" + hash_guid, "hash selector mismatch")
    files = {}
    for role, path in [("boot_image", "unsigned/boot.img"), ("root_data", "nvme/root-data.img"), ("root_hash_tree", "nvme/root-hash.img")]:
        f = unsigned / path
        require(f.is_file() and not f.is_symlink(), "input must be a regular file")
        files[role] = {"digest": digest(f), "size_bytes": f.stat().st_size}
        require(m["artifacts"][role] == {"path": path, "digest": files[role]["digest"]}, "artifact substitution")
    require(files["boot_image"]["size_bytes"] == m["boot_image_size_bytes"], "boot size mismatch")
    root_hash = m["root_integrity_digest"].removeprefix("sha256:")
    subprocess.run(["veritysetup", "verify", str(unsigned / "nvme/root-data.img"), str(unsigned / "nvme/root-hash.img"), root_hash], check=True)
    cmdline = subprocess.check_output(["mtype", "-i", str(unsigned / "unsigned/boot.img"), "::nixos/default/cmdline.txt"]).decode().split()
    for prefix, value in [("roothash=", root_hash), ("systemd.verity_root_data=", "PARTUUID=" + data_guid), ("systemd.verity_root_hash=", "PARTUUID=" + hash_guid)]:
        require([x for x in cmdline if x.startswith(prefix)] == [prefix + value], "signed root binding mismatch")
    inputs.mkdir()
    manifest = dict(schema_version="kaiba.provisioning.rpi5-native-offline-signing-input/v1alpha1", source_revision=source,
                    unsigned_artifacts_digest=digest(unsigned / "manifest.json"), review_digest=digest(review / "review.json"),
                    **files, root_integrity_digest=m["root_integrity_digest"], root_data_partuuid=data_guid, root_hash_partuuid=hash_guid,
                    hardware_observed=False, fleet_admission="unevaluated")
    (inputs / "manifest.json").write_bytes(json.dumps(manifest, separators=(",", ":"), sort_keys=True).encode() + b"\n")
    output.mkdir()
    (output / "boot.img").write_bytes((unsigned / "unsigned/boot.img").read_bytes())
    (output / "public.pem").write_bytes(key.read_bytes())
    intent = dict(schema_version="kaiba.provisioning.rpi5-native-offline-signing-intent/v1alpha1", authorization_scope="native_offline_boot",
                  source_revision=source, source_date_epoch=epoch, unsigned_manifest_digest=digest(inputs / "manifest.json"),
                  expected_customer_key_hash=public["customer_key_hash"], public_key_file_digest=digest(key),
                  public_key_fingerprint=public["public_key_fingerprint"], signer_policy_digest=public["signer_policy_digest"],
                  signing_input=dict(role="rpi5.boot_image", **files["boot_image"]))
    write(output / "release-intent.json", intent)
    intent_digest = "sha256:" + hashlib.sha256(b"kaiba.provisioning.rpi5-native-offline-signing-intent.v1alpha1\0" + encoded(intent)).hexdigest()
    write(output / "plan.json", dict(schema_version="kaiba.provisioning.rpi5-boot-signing-plan/v1alpha2", plan_id="plan:rpi5-native-offline:" + source[:16],
                                    release_intent_digest=intent_digest, boot_image_digest=files["boot_image"]["digest"], boot_image_size_bytes=files["boot_image"]["size_bytes"],
                                    public_key_fingerprint=public["public_key_fingerprint"], signer_policy_digest=public["signer_policy_digest"], source_date_epoch=epoch))


if __name__ == "__main__":
    main()
