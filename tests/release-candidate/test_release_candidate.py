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
        with patch.object(candidate, "run", side_effect=command), patch.object(candidate, "export_closure", side_effect=export):
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
