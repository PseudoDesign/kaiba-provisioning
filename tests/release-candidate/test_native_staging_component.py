import argparse
import copy
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch


SCRIPT = Path(__file__).resolve().parents[2] / ".github/scripts/native_staging_component.py"
SPEC = importlib.util.spec_from_file_location("native_staging_component", SCRIPT)
component = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(component)

CONFIG_PATH = "/nix/store/" + "0" * 32 + "-nvme-config.json"
PLAN_PATH = "/nix/store/" + "1" * 32 + "-staging-plan.json"
PAYLOAD_ROOT = "/nix/store/" + "2" * 32 + "-run-1"
OUTPUT_PATH = "/nix/store/" + "3" * 32 + "-native-component"
NAR = "sha256-" + "A" * 43 + "="


def encoded(value):
    return (json.dumps(value, separators=(",", ":"), sort_keys=True) + "\n").encode()


def bound_json(path, value):
    raw = encoded(value)
    return {"path": path, "sha256": "sha256:" + hashlib.sha256(raw).hexdigest(),
            "size_bytes": len(raw), "json": raw.decode()}


def fixture_descriptor():
    config = {"leg": "pi-local-nvme", "payload_paths": {"release-filesystem": PAYLOAD_ROOT + "/release.img"},
              "schema_version": "kaiba.provisioning.rpi5-stable-campaign-staging-configuration/v1alpha1",
              "staging_plan_path": PLAN_PATH}
    plan_digest = "sha256:" + "4" * 64
    return {
        "schema_version": component.DESCRIPTOR_SCHEMA, "target_system": "aarch64-linux",
        "leg": "pi-local-nvme", "hardware_qualified": False, "production_ready": False,
        "configuration": bound_json(CONFIG_PATH, config),
        "staging_plan": {**bound_json(PLAN_PATH, {"plan_digest": plan_digest}), "plan_digest": plan_digest},
        "payloads": [{"role": "release-filesystem", "path": PAYLOAD_ROOT + "/release.img",
                      "sha256": "sha256:" + "5" * 64, "size_bytes": 4194304,
                      "partition_size_bytes": 8589934592, "whole_partition_sha256": "sha256:" + "6" * 64}],
    }


class NativeComponentTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.repo = self.root / "repo"
        self.repo.mkdir()
        self.git("init", "--quiet", "--initial-branch=main")
        self.git("config", "user.email", "fixture@example.invalid")
        self.git("config", "user.name", "Native fixture")
        self.relative = "review/nvme-descriptor.json"
        self.path = self.repo / self.relative
        self.path.parent.mkdir()
        self.descriptor = fixture_descriptor()
        self.raw = encoded(self.descriptor)
        self.path.write_bytes(self.raw)
        self.git("add", self.relative)
        self.git("commit", "--quiet", "-m", "public descriptor")
        self.revision = self.git("rev-parse", "HEAD")

    def git(self, *arguments):
        return component.candidate.run("git", *arguments, cwd=self.repo)

    def test_committed_descriptor_binds_exact_blob_without_self_referencing_commit(self):
        value, raw, record = component.committed_descriptor(self.repo, self.revision, self.relative)
        self.assertEqual(value, self.descriptor)
        self.assertEqual(raw, self.raw)
        self.assertEqual(record["git_blob"], self.git("rev-parse", f"HEAD:{self.relative}"))
        self.assertEqual(record["sha256"], hashlib.sha256(self.raw).hexdigest())
        self.assertNotIn("source_revision", value)
        self.path.write_bytes(self.raw + b" ")
        with self.assertRaises(ValueError):
            component.committed_descriptor(self.repo, self.revision, self.relative)

    def test_descriptor_reader_rejects_symlinks_hardlinks_fifo_and_overflow(self):
        original = self.path.read_bytes()
        self.path.unlink()
        outside = self.root / "outside.json"
        outside.write_bytes(original)
        self.path.symlink_to(outside)
        with self.assertRaises(ValueError):
            component.committed_descriptor(self.repo, self.revision, self.relative)
        self.path.unlink()
        os.link(outside, self.path)
        with self.assertRaises(ValueError):
            component.committed_descriptor(self.repo, self.revision, self.relative)
        self.path.unlink()
        os.mkfifo(self.path)
        with self.assertRaises(ValueError):
            component.committed_descriptor(self.repo, self.revision, self.relative)
        self.path.unlink()
        with self.path.open("wb") as stream:
            stream.truncate(component.DESCRIPTOR_LIMIT + 1)
        with self.assertRaises(ValueError):
            component.committed_descriptor(self.repo, self.revision, self.relative)

    def test_descriptor_reader_rejects_alias_ancestors_and_noncanonical_names(self):
        for relative in ("../review/input.json", "/tmp/input.json", "review//input.json",
                         "review/./input.json", "review/../input.json", "review/${code}.json", "input.json\n"):
            with self.subTest(relative=relative), self.assertRaises((ValueError, OSError)):
                component.committed_descriptor(self.repo, self.revision, relative)
        alias = self.repo / "alias"
        alias.symlink_to(self.path.parent, target_is_directory=True)
        with self.assertRaises(OSError):
            component.committed_descriptor(self.repo, self.revision, "alias/nvme-descriptor.json")

    def test_closed_descriptor_rejects_duplicate_alias_private_and_rebound_changes(self):
        self.assertEqual(component.validate_descriptor(self.raw), self.descriptor)
        bad = [self.raw.replace(b'"leg":', b'"leg":"pi-local-nvme","leg":', 1),
               self.raw.replace(b'"leg":', b'"LEG":', 1)]
        for key, replacement in (("source_revision", "a" * 40), ("target_system", "x86_64-linux"),
                                 ("leg", "malak-sd"), ("hardware_qualified", True), ("production_ready", 0)):
            value = copy.deepcopy(self.descriptor)
            value[key] = replacement
            bad.append(encoded(value))
        for field, replacement in (("json", "-----BEGIN PRIVATE KEY-----"), ("sha256", "sha256:" + "f" * 64),
                                   ("size_bytes", True), ("path", "/tmp/config.json"),
                                   ("path", CONFIG_PATH + "/../escape")):
            value = copy.deepcopy(self.descriptor)
            value["configuration"][field] = replacement
            bad.append(encoded(value))
        value = copy.deepcopy(self.descriptor)
        value["payloads"].append(value["payloads"][0])
        bad.append(encoded(value))
        value = copy.deepcopy(self.descriptor)
        value["configuration"] = bound_json(CONFIG_PATH, {"value": "-----BEGIN PRIVATE KEY-----"})
        bad.append(encoded(value))
        for data in bad:
            with self.subTest(data=data[:80]), self.assertRaises(ValueError):
                component.validate_descriptor(data)

    def make_component(self):
        output = self.root / "component"
        (output / "bin").mkdir(parents=True)
        (output / "share/kaiba").mkdir(parents=True)
        binary = bytearray(128)
        binary[:7] = b"\x7fELF\x02\x01\x01"
        binary[18:20] = (183).to_bytes(2, "little")
        binary.extend(CONFIG_PATH.encode())
        (output / "bin/kaiba-rpi5-stable-campaign-stage").write_bytes(binary)
        (output / "share/kaiba/descriptor.json").write_bytes(self.raw)
        manifest = {
            "schema_version": component.COMPONENT_SCHEMA, "source_revision": self.revision,
            "descriptor_sha256": "sha256:" + hashlib.sha256(self.raw).hexdigest(),
            "configuration_path": CONFIG_PATH,
            "configuration_sha256": self.descriptor["configuration"]["sha256"],
            "target_system": "aarch64-linux", "leg": "pi-local-nvme",
            "binary": {"path": "bin/kaiba-rpi5-stable-campaign-stage", "size_bytes": len(binary),
                       "sha256": "sha256:" + hashlib.sha256(binary).hexdigest()},
            "complete_runtime_closure": False, "hardware_qualified": False, "production_ready": False,
        }
        (output / "share/kaiba/component.json").write_bytes(encoded(manifest))
        return output, manifest

    def test_component_is_byte_bound_arm_and_explicitly_incomplete(self):
        output, manifest = self.make_component()
        self.assertEqual(component.validate_component(output, self.descriptor, self.raw, self.revision), manifest)
        for key, replacement in (("source_revision", "f" * 40), ("descriptor_sha256", "sha256:" + "f" * 64),
                                 ("configuration_path", PLAN_PATH), ("configuration_sha256", "sha256:" + "f" * 64),
                                 ("target_system", "x86_64-linux"), ("complete_runtime_closure", True),
                                 ("hardware_qualified", 0), ("production_ready", True)):
            changed = {**manifest, key: replacement}
            (output / "share/kaiba/component.json").write_bytes(encoded(changed))
            with self.subTest(key=key), self.assertRaises(ValueError):
                component.validate_component(output, self.descriptor, self.raw, self.revision)
        (output / "share/kaiba/component.json").write_bytes(encoded(manifest))
        binary = output / "bin/kaiba-rpi5-stable-campaign-stage"
        raw = bytearray(binary.read_bytes())
        raw[18:20] = (62).to_bytes(2, "little")
        binary.write_bytes(raw)
        manifest["binary"]["sha256"] = "sha256:" + hashlib.sha256(raw).hexdigest()
        (output / "share/kaiba/component.json").write_bytes(encoded(manifest))
        with self.assertRaisesRegex(ValueError, "AArch64"):
            component.validate_component(output, self.descriptor, self.raw, self.revision)

    def test_component_rejects_extra_and_symbolic_outputs(self):
        output, _ = self.make_component()
        extra = output / "boot.img"
        extra.touch()
        with self.assertRaisesRegex(ValueError, "file set"):
            component.validate_component(output, self.descriptor, self.raw, self.revision)
        extra.unlink()
        extra.symlink_to(output / "share/kaiba/descriptor.json")
        with self.assertRaisesRegex(ValueError, "symbolic"):
            component.validate_component(output, self.descriptor, self.raw, self.revision)

    def test_closure_rejects_large_media_and_missing_transitive_bindings(self):
        paths = sorted([CONFIG_PATH, OUTPUT_PATH])
        records = {p: {"narHash": NAR, "narSize": 1024, "references": []} for p in paths}
        records[OUTPUT_PATH]["references"] = [CONFIG_PATH]
        with patch.object(component.candidate, "path_metadata", return_value=records):
            actual = component.closure_metadata(paths, self.descriptor)
        self.assertEqual(actual[OUTPUT_PATH]["references"], [CONFIG_PATH])
        with patch.object(component.candidate, "path_metadata") as query:
            for paths_bad in (sorted(paths + [PLAN_PATH]), sorted(paths + [PAYLOAD_ROOT]), paths[::-1], paths + paths):
                with self.assertRaises(ValueError):
                    component.closure_metadata(paths_bad, self.descriptor)
            query.assert_not_called()
        for field, replacement in (("narSize", component.CLOSURE_LIMIT + 1), ("narSize", True),
                                   ("references", [PLAN_PATH]), ("narHash", "not a NAR hash")):
            changed = copy.deepcopy(records)
            changed[OUTPUT_PATH][field] = replacement
            with patch.object(component.candidate, "path_metadata", return_value=changed), self.assertRaises(ValueError):
                component.closure_metadata(paths, self.descriptor)

    def test_expression_pins_native_build_descriptor_source_without_runtime_calls(self):
        value = component.expression("git+file:///fixture?rev=" + self.revision, self.relative, self.revision)
        self.assertIn("lib.mkRpi5StableCampaignStagingNativeComponent", value)
        self.assertIn('builtins.currentSystem == "aarch64-linux"', value)
        self.assertIn('component.system == "aarch64-linux"', value)
        self.assertIn('descriptor = f.outPath + "/review/nvme-descriptor.json"', value)
        self.assertIn('f.rev == "' + self.revision + '"', value)
        self.assertNotIn("stagingPlan =", value)
        self.assertNotIn("payloads =", value)

    def test_descriptor_agrees_with_constructor_helper_using_real_plan_contract(self):
        repository = SCRIPT.parents[2]
        helper_spec = importlib.util.spec_from_file_location(
            "campaign_staging_inputs", repository / "nix/campaign-staging-inputs.py")
        helper = importlib.util.module_from_spec(helper_spec)
        helper_spec.loader.exec_module(helper)
        raw_plan = (repository / "internal/provisioning/campaignmedia/testdata/recovery-v1alpha2/staging-plan.json").read_bytes()
        plan = json.loads(raw_plan)
        partition = plan["devices"][1]["partitions"][0]
        value = copy.deepcopy(self.descriptor)
        value["staging_plan"] = {"path": PLAN_PATH, "json": raw_plan.decode(),
                                 "size_bytes": len(raw_plan), "plan_digest": plan["plan_digest"],
                                 "sha256": "sha256:" + hashlib.sha256(raw_plan).hexdigest()}
        value["payloads"][0].update({"sha256": partition["source_sha256"],
                                     "size_bytes": partition["source_size_bytes"],
                                     "whole_partition_sha256": partition["expected_whole_partition_sha256"]})
        data = encoded(value)
        with patch.object(helper, "open_regular") as reader:
            self.assertEqual(helper.validate(data), component.validate_descriptor(data))
            reader.assert_not_called()

    def test_export_records_every_nar_descriptor_and_incomplete_boundary(self):
        _, manifest = self.make_component()
        paths = sorted([CONFIG_PATH, OUTPUT_PATH])
        records = {p: {"narHash": NAR, "narSize": 1024, "references": []} for p in paths}
        records[OUTPUT_PATH]["references"] = [CONFIG_PATH]
        real_run = component.candidate.run
        commands = []

        def run(*args, **kwargs):
            commands.append(args)
            if args[:3] == ("nix", "--accept-flake-config", "build"):
                self.assertIn("--no-update-lock-file", args)
                self.assertIn("--no-write-lock-file", args)
                return json.dumps([{"outputs": {"out": OUTPUT_PATH}}])
            if args == ("nix-store", "--query", "--requisites", OUTPUT_PATH):
                return "\n".join(paths)
            if args == ("nix", "--version"):
                return "nix fixture"
            return real_run(*args, **kwargs)

        def export(selected, destination):
            self.assertEqual(selected, [OUTPUT_PATH])
            destination.write_bytes(b"public component archive fixture")
            return paths

        output = self.root / "export"
        args = argparse.Namespace(repository=self.repo, source_sha=self.revision, main_sha=self.revision,
                                  workflow_sha="f" * 40, descriptor=self.relative, output=output)
        with patch.object(component.candidate, "run", side_effect=run), \
                patch.object(component.candidate, "require_native_system") as native, \
                patch.object(component, "validate_component", return_value=manifest), \
                patch.object(component.candidate, "path_metadata", return_value=records), \
                patch.object(component.candidate, "export_closure", side_effect=export):
            component.build(args)
        native.assert_called_once_with("aarch64-linux")
        provenance = json.loads((output / "provenance.json").read_bytes())
        self.assertEqual(provenance["workflow_revision"], "f" * 40)
        self.assertEqual(provenance["source_revision"], self.revision)
        self.assertEqual(provenance["exported_store_paths"], paths)
        self.assertEqual(set(provenance["exported_store_path_metadata"]), set(paths))
        self.assertEqual((output / "descriptor.json").read_bytes(), self.raw)
        for key in ("complete_staging_runtime_closure", "payloads_exported", "component_executed",
                    "signing_performed", "hardware_observed", "production_ready"):
            self.assertIs(provenance[key], False)
        for line in (output / "SHA256SUMS").read_text().splitlines():
            digest, filename = line.split("  ")
            self.assertEqual(digest, hashlib.sha256((output / filename).read_bytes()).hexdigest())
        self.assertFalse(any("run" in command or "prepare" in command or "execute" in command for command in commands))
        self.assertIn("not a complete staging runtime", (output / "SUMMARY.md").read_text())

    def test_source_selection_rejects_other_branches(self):
        self.assertEqual(component.candidate.select_source(self.repo, self.revision, self.revision,
                                                          "refs/heads/main"), self.revision)
        with self.assertRaises(ValueError):
            component.candidate.select_source(self.repo, self.revision, self.revision, "refs/heads/feature")


if __name__ == "__main__":
    unittest.main()
