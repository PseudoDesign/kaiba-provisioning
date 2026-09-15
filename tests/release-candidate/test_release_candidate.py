import argparse
import gzip
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest
from unittest.mock import patch


SCRIPT = Path(__file__).resolve().parents[2] / ".github/scripts/release_candidate.py"
SPEC = importlib.util.spec_from_file_location("release_candidate", SCRIPT)
candidate = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(candidate)


class CandidateTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.repo = self.root / "repo"
        self.repo.mkdir()
        self.git("init", "--quiet", "--initial-branch=fixture-base")
        self.git("config", "user.email", "test@example.invalid")
        self.git("config", "user.name", "Candidate test")
        self.git("commit", "--quiet", "--allow-empty", "-m", "base")
        self.base = self.git("rev-parse", "HEAD")
        self.git("checkout", "--quiet", "-b", "side")
        self.git("commit", "--quiet", "--allow-empty", "-m", "side")
        self.side = self.git("rev-parse", "HEAD")
        self.git("checkout", "--quiet", "-b", "main", self.base)
        self.git("commit", "--quiet", "--allow-empty", "-m", "main")
        self.head = self.git("rev-parse", "HEAD")

    def git(self, *args):
        return candidate.run("git", *args, cwd=self.repo)

    def test_selects_exact_main_tip_or_ancestor(self):
        for sha in (self.base, self.head):
            self.assertEqual(candidate.select_source(self.repo, sha, self.head, "refs/heads/main"), sha)

    def test_rejects_ambiguous_revisions_before_git(self):
        with patch.object(candidate, "run") as run:
            for sha in ("main", self.base[:12], self.base.upper(), "0" * 40 + "\n", "$(id)", "--help"):
                with self.subTest(sha=sha), self.assertRaises(ValueError):
                    candidate.select_source(self.repo, sha, self.head, "refs/heads/main")
            run.assert_not_called()

    def test_rejects_unmerged_commit_other_workflow_branch_and_wrong_main(self):
        with self.assertRaises(subprocess.CalledProcessError):
            candidate.select_source(self.repo, self.side, self.head, "refs/heads/main")
        with self.assertRaises(ValueError):
            candidate.select_source(self.repo, self.head, self.head, "refs/heads/side")
        with self.assertRaises(ValueError):
            candidate.select_source(self.repo, self.base, self.base, "refs/heads/main")
        tree = self.git("rev-parse", "HEAD^{tree}")
        with self.assertRaises(ValueError):
            candidate.select_source(self.repo, tree, self.head, "refs/heads/main")

    def test_requires_exact_clean_candidate_checkout(self):
        candidate.require_clean_checkout(self.repo, self.head)
        with self.assertRaises(ValueError):
            candidate.require_clean_checkout(self.repo, self.base)
        (self.repo / "untracked").write_text("change")
        with self.assertRaises(ValueError):
            candidate.require_clean_checkout(self.repo, self.head)

    def public_inputs(self):
        unsigned = self.root / "unsigned"
        plan = self.root / "plan"
        unsigned.mkdir()
        plan.mkdir()
        manifest = {"source_revision": self.head, "bundle_digest": "sha256:" + "a" * 64}
        (unsigned / "manifest.json").write_text(json.dumps(manifest) + "\n")
        intent = {
            "source_revision": self.head,
            "unsigned_manifest_digest": "sha256:" + candidate.file_sha256(unsigned / "manifest.json"),
            "unsigned_artifact_set_digest": manifest["bundle_digest"],
        }
        (plan / "release-intent.json").write_text(json.dumps(intent) + "\n")
        (plan / "plan.json").write_text('{"fixture": true}\n')
        (plan / "public.pem").write_text("public fixture\n")
        return unsigned, plan

    def test_rejects_source_and_manifest_transplants(self):
        unsigned, plan = self.public_inputs()
        candidate.validate_public_lineage(unsigned, plan, self.head)
        for key in ("source_revision", "unsigned_manifest_digest", "unsigned_artifact_set_digest"):
            original = (plan / "release-intent.json").read_bytes()
            intent = json.loads(original)
            intent[key] = self.base
            (plan / "release-intent.json").write_text(json.dumps(intent))
            with self.subTest(key=key), self.assertRaises(ValueError):
                candidate.validate_public_lineage(unsigned, plan, self.head)
            (plan / "release-intent.json").write_bytes(original)
        (unsigned / "manifest.json").write_text('{"source_revision": "wrong"}')
        with self.assertRaises(ValueError):
            candidate.validate_public_lineage(unsigned, plan, self.head)

    def test_requires_nar_metadata_for_every_output(self):
        for records in ({}, {"/one": {}}, {"/other": {"narHash": "sha256-example"}}):
            with patch.object(candidate, "run", return_value=json.dumps(records)), self.assertRaises(ValueError):
                candidate.path_metadata(["/one"])
        for records in ({"/one": {"narHash": "sha256-example"}}, [{"path": "/one", "narHash": "sha256-example"}]):
            with patch.object(candidate, "run", return_value=json.dumps(records)):
                self.assertEqual(candidate.path_metadata(["/one"])["/one"]["narHash"], "sha256-example")

    def test_report_binds_actual_outputs_archive_and_distinct_workflow_revision(self):
        unsigned, plan = self.public_inputs()
        output = self.root / "export"
        real_run = candidate.run
        paths = [str(unsigned), str(plan)]

        def command(*args, **kwargs):
            if args == ("nix", "--version"):
                return "nix (test fixture)"
            if args[:3] == ("nix", "--accept-flake-config", "build"):
                self.assertIn("--no-update-lock-file", args)
                self.assertIn("--no-write-lock-file", args)
                self.assertIn(f"?rev={self.head}#packages.aarch64-linux.", args[-1])
                path = unsigned if args[-1].endswith("-unsigned") else plan
                return json.dumps([{"outputs": {"out": str(path)}}])
            if args[:3] == ("nix", "path-info", "--json"):
                return json.dumps({path: {"narHash": "sha256-" + str(index)} for index, path in enumerate(paths)})
            return real_run(*args, **kwargs)

        def export(selected, destination):
            self.assertEqual(selected, paths)
            destination.write_bytes(b"complete exported closure fixture")
            return paths + ["/nix/store/transitive-dependency"]

        args = argparse.Namespace(repository=self.repo, source_sha=self.head, main_sha=self.head,
                                  workflow_sha=self.base, system="aarch64-linux", output=output)
        with patch.object(candidate, "run", side_effect=command), patch.object(candidate, "export_closure", side_effect=export), \
                patch.object(candidate, "require_native_system"):
            candidate.build(args)
        report = json.loads((output / "provenance.json").read_text())
        self.assertEqual(report["source_revision"], self.head)
        self.assertEqual(report["workflow_revision"], self.base)
        self.assertEqual(report["nix_version"], "nix (test fixture)")
        self.assertEqual(report["outputs"]["unsigned"]["path"], str(unsigned))
        self.assertEqual(report["outputs"]["signing-plan"]["nar_hash"], "sha256-1")
        self.assertIn("/nix/store/transitive-dependency", report["exported_store_paths"])
        self.assertEqual(report["archive"]["sha256"], candidate.file_sha256(output / "nix-store-export.gz"))
        self.assertFalse(report["signing_performed"])
        self.assertFalse(report["hardware_observed"])
        for line in (output / "SHA256SUMS").read_text().splitlines():
            digest, name = line.split("  ")
            self.assertEqual(digest, hashlib.sha256((output / name).read_bytes()).hexdigest())

    def committed_verifier_inputs(self):
        relative = "review/verifier"
        directory = self.repo / relative
        directory.mkdir(parents=True)
        config = {
            "schema_version": candidate.CONFIG_SCHEMA,
            "verifier_version": 1,
            "minimum_security_epoch": 1,
            "cohort_id": "development-pi5",
            "slot_id": "a",
            "authority_url": "https://authority.example.invalid:8443",
            "authority_key_id": "authority:fixture",
            "audience": "verifier-fixture",
            "logical_identity": "development-pi5",
        }
        (directory / "candidate.json").write_text(json.dumps(config) + "\n")
        (directory / "policy.json").write_text('{"public_policy_fixture":true}\n')
        (directory / "root-public.pem").write_text("public root fixture\n")
        (directory / "authority-ca.pem").write_text("public certificate fixture\n")
        self.git("add", relative)
        self.git("commit", "--quiet", "-m", "reviewed public inputs")
        self.head = self.git("rev-parse", "HEAD")
        return relative, directory, config

    def test_public_inputs_bind_exact_selected_git_blobs(self):
        relative, directory, config = self.committed_verifier_inputs()
        actual, selected, records, payloads = candidate.validate_public_inputs(self.repo, self.head, relative)
        self.assertEqual(actual, directory)
        self.assertEqual(selected, config)
        self.assertEqual(set(records), set(candidate.PUBLIC_INPUT_LIMITS))
        for name, record in records.items():
            self.assertEqual(record["sha256"], candidate.file_sha256(directory / name))
            self.assertEqual(payloads[name], (directory / name).read_bytes())
            self.assertEqual(record["git_blob"], self.git("rev-parse", f"{self.head}:{relative}/{name}"))
        with self.assertRaises(ValueError):
            candidate.validate_public_inputs(self.repo, self.base, relative)
        self.git("update-index", "--assume-unchanged", relative + "/policy.json")
        (directory / "policy.json").write_text('{"public_policy_fixture":false}\n')
        candidate.require_clean_checkout(self.repo, self.head)
        with self.assertRaises(ValueError):
            candidate.validate_public_inputs(self.repo, self.head, relative)

    def test_public_inputs_reject_paths_and_symlink_ancestors(self):
        relative, directory, _ = self.committed_verifier_inputs()
        for path in ("", ".", "../review/verifier", "/tmp/public", "review/../review/verifier",
                     "review//verifier", "review/./verifier", "review/verifier/", "review/${bad}"):
            with self.subTest(path=path), self.assertRaises(ValueError):
                candidate.validate_public_inputs(self.repo, self.head, path)
        (self.repo / "alias").symlink_to(directory.parent, target_is_directory=True)
        with self.assertRaises(ValueError):
            candidate.validate_public_inputs(self.repo, self.head, "alias/verifier")

    def test_public_inputs_reject_nonplain_extra_oversized_and_private_files(self):
        relative, directory, _ = self.committed_verifier_inputs()
        path = directory / "root-public.pem"
        original = path.read_bytes()
        for mutation in ("symlink", "hardlink", "fifo", "directory", "oversize", "private"):
            with self.subTest(mutation=mutation):
                path.unlink()
                if mutation == "symlink":
                    path.symlink_to(directory / "authority-ca.pem")
                elif mutation == "hardlink":
                    os.link(directory / "authority-ca.pem", path)
                elif mutation == "fifo":
                    os.mkfifo(path)
                elif mutation == "directory":
                    path.mkdir()
                elif mutation == "oversize":
                    path.write_bytes(b"x" * (candidate.PUBLIC_INPUT_LIMITS[path.name] + 1))
                else:
                    path.write_bytes(b"-----BEGIN RSA PRIVATE KEY-----\nfixture\n")
                with self.assertRaises(ValueError):
                    candidate.validate_public_inputs(self.repo, self.head, relative)
                path.rmdir() if mutation == "directory" else path.unlink()
                path.write_bytes(original)
        (directory / "unreviewed").write_text("extra")
        with self.assertRaises(ValueError):
            candidate.validate_public_inputs(self.repo, self.head, relative)

    def test_candidate_config_is_closed_and_bounded(self):
        _, _, config = self.committed_verifier_inputs()
        valid = json.dumps(config)
        self.assertEqual(candidate.validate_config(valid), config)
        mutations = [
            valid[:-1] + ',"slot_id":"b"}',
            json.dumps({**config, "extra_modules": []}),
            json.dumps({key: value for key, value in config.items() if key != "audience"}),
            json.dumps({**config, "verifier_version": True}),
            json.dumps({**config, "minimum_security_epoch": 0}),
            json.dumps({**config, "verifier_version": 2147483648}),
            json.dumps({**config, "cohort_id": "bad cohort"}),
        ]
        for url in ("http://host", "https://user:password@host", "https://host/#fragment",
                    "https://host/\npath", "https://host:99999", "https://", "https://host:0",
                    "https://host/api", "https://host?x=1"):
            mutations.append(json.dumps({**config, "authority_url": url}))
        for encoded in mutations:
            with self.subTest(encoded=encoded), self.assertRaises(ValueError):
                candidate.validate_config(encoded)

    def test_native_build_gate_checks_kernel_and_nix_platform(self):
        with patch.object(candidate.platform, "system", return_value="Linux"), \
                patch.object(candidate.platform, "machine", return_value="x86_64"), \
                patch.object(candidate, "run") as run:
            with self.assertRaises(ValueError):
                candidate.require_native_system("aarch64-linux")
            run.assert_not_called()
        with patch.object(candidate.platform, "system", return_value="Linux"), \
                patch.object(candidate.platform, "machine", return_value="aarch64"), \
                patch.object(candidate, "run", return_value="x86_64-linux"):
            with self.assertRaises(ValueError):
                candidate.require_native_system("aarch64-linux")
        with patch.object(candidate.platform, "system", return_value="Linux"), \
                patch.object(candidate.platform, "machine", return_value="aarch64"), \
                patch.object(candidate, "run", return_value="aarch64-linux"):
            candidate.require_native_system("aarch64-linux")

    def test_verifier_expression_fixes_source_profile_and_platform(self):
        expression = candidate.verifier_expression('git+file:///tmp/${unsafe}?rev=' + self.head,
                                                    "review/verifier", self.head, 123, "unsignedBoot")
        self.assertIn(r"\${unsafe}", expression)
        self.assertIn('publicInputs = f.outPath + "/review/verifier"', expression)
        self.assertIn(f'assert f.rev == "{self.head}"', expression)
        self.assertIn('assert builtins.currentSystem == "aarch64-linux"', expression)
        self.assertIn('assert candidate.unsignedBoot.system == "aarch64-linux"', expression)
        self.assertIn("sourceDateEpoch = 123", expression)
        with self.assertRaises(ValueError):
            candidate.verifier_expression("flake", "path", self.head, 1, "sign")

    def verifier_public_outputs(self, epoch):
        unsigned = self.root / "verifier-unsigned"
        plan = self.root / "verifier-plan"
        unsigned.mkdir()
        plan.mkdir()
        for directory in (unsigned, plan):
            with (directory / "boot.img").open("wb") as stream:
                stream.truncate(96 * 1024 * 1024)
        boot = {"path": "boot.img", "sha256": "sha256:" + candidate.file_sha256(unsigned / "boot.img"),
                "size_bytes": 96 * 1024 * 1024}
        manifest = {"schema_version": "kaiba.provisioning.rpi5-stable-verifier-boot-artifact/v1alpha1",
                    "source_revision": self.head, "boot_image": boot}
        (unsigned / "manifest.json").write_text(json.dumps(manifest) + "\n")
        intent = {
            "schema_version": "kaiba.provisioning.rpi5-stable-campaign-verifier-signing-intent/v1alpha1",
            "authorization_scope": "stable_campaign_verifier_boot",
            "source_revision": self.head,
            "source_date_epoch": epoch,
            "unsigned_manifest_digest": "sha256:" + candidate.file_sha256(unsigned / "manifest.json"),
            "signing_input": {"role": "rpi5.boot_image", "digest": boot["sha256"], "size_bytes": boot["size_bytes"]},
        }
        (plan / "release-intent.json").write_text(json.dumps(intent) + "\n")
        (plan / "plan.json").write_text(json.dumps({"source_date_epoch": epoch}) + "\n")
        (plan / "public.pem").write_text("public fixture\n")
        return unsigned, plan

    def test_verifier_lineage_rejects_source_epoch_profile_and_image_substitution(self):
        unsigned, plan = self.verifier_public_outputs(123)
        with patch.object(candidate, "run", return_value='{"status":"valid"}'):
            candidate.validate_verifier_lineage(unsigned, plan, self.head, 123, "flake")
            for key, value in (("source_revision", self.base), ("source_date_epoch", 124),
                               ("authorization_scope", "stable_campaign_provisioner_boot"),
                               ("unsigned_manifest_digest", "sha256:" + "0" * 64)):
                original = (plan / "release-intent.json").read_bytes()
                changed = json.loads(original)
                changed[key] = value
                (plan / "release-intent.json").write_text(json.dumps(changed))
                with self.subTest(key=key), self.assertRaises(ValueError):
                    candidate.validate_verifier_lineage(unsigned, plan, self.head, 123, "flake")
                (plan / "release-intent.json").write_bytes(original)
            with (plan / "boot.img").open("r+b") as stream:
                stream.write(b"changed")
            with self.assertRaises(ValueError):
                candidate.validate_verifier_lineage(unsigned, plan, self.head, 123, "flake")

    def test_verifier_export_uses_committed_inputs_and_retains_their_hashes(self):
        relative, directory, config = self.committed_verifier_inputs()
        epoch = candidate.source_epoch(self.repo, self.head)
        unsigned, plan = self.verifier_public_outputs(epoch)
        output = self.root / "verifier-export"
        paths = [str(unsigned), str(plan)]
        real_run = candidate.run
        operations = []

        def command(*args, **kwargs):
            if args == ("nix", "--version"):
                return "nix (verifier test)"
            if args[:3] == ("nix", "--accept-flake-config", "build"):
                self.assertIn("--no-update-lock-file", args)
                self.assertIn("--no-write-lock-file", args)
                self.assertIn("--expr", args)
                self.assertIn(f'sourceRevision = "{self.head}"', args[-1])
                self.assertIn(f'sourceDateEpoch = {epoch}', args[-1])
                self.assertIn('f.outPath + "/review/verifier"', args[-1])
                path = unsigned if args[-1].endswith("candidate.unsignedBoot") else plan
                return json.dumps([{"outputs": {"out": str(path)}}])
            if args[:3] == ("nix", "--accept-flake-config", "run"):
                operations.append(args[args.index("--") + 1])
                return '{"status":"valid"}'
            if args[:3] == ("nix", "path-info", "--json"):
                return json.dumps({path: {"narHash": "sha256-fixture"} for path in paths})
            return real_run(*args, **kwargs)

        def export(selected, destination):
            self.assertEqual(selected, paths)
            destination.write_bytes(b"verifier closure fixture")
            return paths

        args = argparse.Namespace(repository=self.repo, source_sha=self.head, main_sha=self.head,
                                  workflow_sha=self.base, system="aarch64-linux", output=output,
                                  profile="verifier", public_inputs=relative)
        with patch.object(candidate, "run", side_effect=command), \
                patch.object(candidate, "require_native_system") as native, \
                patch.object(candidate, "export_closure", side_effect=export):
            candidate.build(args)
        native.assert_called_once_with("aarch64-linux")
        self.assertEqual(operations, ["validate-plan", "validate-unsigned"])
        report = json.loads((output / "provenance.json").read_text())
        self.assertEqual(report["profile"], "verifier")
        self.assertEqual(report["source_date_epoch"], epoch)
        self.assertEqual(report["public_inputs"]["configuration"], config)
        for name, metadata in report["public_inputs"]["files"].items():
            self.assertEqual((output / "public-inputs" / name).read_bytes(), (directory / name).read_bytes())
            self.assertEqual(metadata["sha256"], candidate.file_sha256(directory / name))
        for line in (output / "SHA256SUMS").read_text().splitlines():
            digest, name = line.split("  ")
            self.assertEqual(digest, candidate.file_sha256(output / name))

    def test_x86_verifier_export_requires_same_public_inputs_and_only_builds_runtime(self):
        relative, directory, _ = self.committed_verifier_inputs()
        runtime = self.root / "runtime"
        runtime.mkdir()
        output = self.root / "x86-export"
        real_run = candidate.run
        builds = []

        def command(*args, **kwargs):
            if args == ("nix", "--version"):
                return "nix (fixture)"
            if args[:3] == ("nix", "--accept-flake-config", "build"):
                builds.append(args[-1])
                return json.dumps([{"outputs": {"out": str(runtime)}}])
            if args[:3] == ("nix", "path-info", "--json"):
                return json.dumps({str(runtime): {"narHash": "sha256-runtime"}})
            if args[:3] == ("nix", "--accept-flake-config", "run"):
                self.fail("x86 export must not invoke the configured signing runtime")
            return real_run(*args, **kwargs)

        def export(paths, destination):
            destination.write_bytes(b"runtime closure fixture")
            return paths

        args = argparse.Namespace(repository=self.repo, source_sha=self.head, main_sha=self.head,
                                  workflow_sha=self.base, system="x86_64-linux", output=output,
                                  profile="verifier", public_inputs=relative)
        with patch.object(candidate, "run", side_effect=command), \
                patch.object(candidate, "require_native_system") as native, \
                patch.object(candidate, "export_closure", side_effect=export):
            candidate.build(args)
        native.assert_called_once_with("x86_64-linux")
        self.assertEqual(len(builds), 1)
        self.assertTrue(builds[0].endswith("#packages.x86_64-linux.kaiba-rpi5-stable-verifier-development-signing"))
        self.assertEqual((output / "public-inputs" / "candidate.json").read_bytes(),
                         (directory / "candidate.json").read_bytes())
        args.public_inputs = ""
        args.output = self.root / "rejected-export"
        with patch.object(candidate, "require_native_system") as native, self.assertRaises(ValueError):
            candidate.build(args)
        native.assert_not_called()
        self.assertFalse(args.output.exists())

    @unittest.skipUnless(shutil.which("nix"), "Nix is needed for the isolated store round trip")
    def test_export_import_retains_transitive_closure_in_empty_store(self):
        source_store = "local?root=" + str(self.root / "source-store")
        target_store = "local?root=" + str(self.root / "target-store")
        with patch.dict(os.environ, {"NIX_REMOTE": source_store}):
            path = candidate.run(
                "nix", "eval", "--raw", "--expr",
                'let dependency = builtins.toFile "candidate-dependency" "retained dependency bytes"; '
                'in builtins.toFile "candidate-root" ("root references " + dependency)',
            )
            metadata = candidate.path_metadata([path])
            closure = candidate.export_closure([path], self.root / "export.gz")
            self.assertEqual(len(closure), 2)
        with gzip.open(self.root / "export.gz", "rb") as archive:
            imported = subprocess.run(
                ["nix-store", "--store", target_store, "--import"],
                input=archive.read(), stdout=subprocess.PIPE, check=True,
            ).stdout.decode().splitlines()
        self.assertEqual(set(imported), set(closure))
        with patch.dict(os.environ, {"NIX_REMOTE": target_store}):
            restored = candidate.path_metadata([path])
        self.assertEqual(restored[path]["narHash"], metadata[path]["narHash"])
        for path in closure:
            self.assertEqual(
                (self.root / "source-store" / path.lstrip("/")).read_bytes(),
                (self.root / "target-store" / path.lstrip("/")).read_bytes(),
            )


if __name__ == "__main__":
    unittest.main()
