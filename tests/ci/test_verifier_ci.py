import importlib.util
import os
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch


ROOT = Path(__file__).resolve().parents[2]
SPEC = importlib.util.spec_from_file_location("verifier_ci", ROOT / ".github/scripts/verifier_ci.py")
ci = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(ci)


def identities(letter="a"):
    return {name: f"/nix/store/{letter * 32}-{name}.drv" for name in ci.VERIFIER_CHECKS}


class SelectionTests(unittest.TestCase):
    def test_unchanged_skips_both_and_changed_selects_only_affected_variant(self):
        before = identities()
        self.assertEqual(ci.changed_checks(before, before.copy()), [])
        for name in ci.VERIFIER_CHECKS:
            after = before | {name: identities("b")[name]}
            self.assertEqual(ci.changed_checks(before, after), [name])
        self.assertEqual(ci.changed_checks(before, identities("b")), list(ci.VERIFIER_CHECKS))

    def test_missing_or_invalid_identity_cannot_be_reported_unchanged(self):
        for value in ({}, [], identities() | {"new-check": "anything"},
                      {name: "not-a-derivation" for name in ci.VERIFIER_CHECKS}):
            with self.subTest(value=value), self.assertRaises(ValueError):
                ci.changed_checks(value, identities())

    def test_main_and_manual_runs_always_build_both(self):
        for event in ("push", "workflow_dispatch"):
            with self.subTest(event=event), patch.object(ci, "identities", return_value=identities()):
                self.assertEqual(ci.plan(ROOT, event)["checks"], list(ci.VERIFIER_CHECKS))

    def test_pr_requires_a_canonical_base_and_rejects_unknown_events(self):
        for event, base in (("pull_request", None), ("pull_request", "main"),
                            ("pull_request", "--help"), ("schedule", "a" * 40)):
            with self.subTest(event=event, base=base), patch.object(
                ci, "identities", return_value=identities()
            ), self.assertRaises(ValueError):
                ci.plan(ROOT, event, base)

    def test_real_git_base_checkout_is_removed_after_evaluation_failure(self):
        with tempfile.TemporaryDirectory() as directory:
            repo = Path(directory)
            env = os.environ | {
                "GIT_AUTHOR_NAME": "CI test", "GIT_AUTHOR_EMAIL": "ci@example.invalid",
                "GIT_COMMITTER_NAME": "CI test", "GIT_COMMITTER_EMAIL": "ci@example.invalid",
            }
            subprocess.run(["git", "init", "-q", str(repo)], check=True)
            subprocess.run(["git", "-C", str(repo), "-c", "commit.gpgsign=false",
                            "commit", "-qm", "base", "--allow-empty"], env=env, check=True)
            base = subprocess.check_output(["git", "-C", str(repo), "rev-parse", "HEAD"], text=True).strip()
            for failure in (False, True):
                calls = []

                def evaluate(path):
                    calls.append(path)
                    self.assertEqual(subprocess.check_output(
                        ["git", "-C", str(path), "rev-parse", "HEAD"], text=True
                    ).strip(), base)
                    if failure and path != repo:
                        raise subprocess.CalledProcessError(1, "nix eval")
                    return identities()

                with self.subTest(failure=failure), patch.object(ci, "identities", side_effect=evaluate):
                    if failure:
                        with self.assertRaises(subprocess.CalledProcessError):
                            ci.plan(repo, "pull_request", base)
                    else:
                        self.assertEqual(ci.plan(repo, "pull_request", base)["checks"], [])
                self.assertFalse(calls[-1].exists())
                listing = subprocess.check_output(["git", "-C", str(repo), "worktree", "list"], text=True)
                self.assertEqual(len(listing.splitlines()), 1)

    def test_partition_keeps_all_other_and_future_checks(self):
        ordinary = ["unit", "device-secret-development", "a-new-future-check"]
        names = sorted(ordinary + list(ci.VERIFIER_CHECKS))
        self.assertEqual(ci.ordinary_checks(names), sorted(ordinary))
        self.assertEqual(set(ci.ordinary_checks(names)) | set(ci.VERIFIER_CHECKS), set(names))
        for malformed in ([], names + ["unit"], names + ["../bad"]):
            with self.subTest(malformed=malformed), self.assertRaises(ValueError):
                ci.ordinary_checks(malformed)

    def test_ordinary_build_refuses_non_native_host(self):
        with patch.object(ci.platform, "machine", return_value="x86_64"), patch.object(
            ci.subprocess, "run"
        ) as run, self.assertRaises(ValueError):
            ci.build_ordinary(ROOT)
        run.assert_not_called()


class RequiredResultTests(unittest.TestCase):
    def setUp(self):
        self.results = dict.fromkeys(
            ("CORE_RESULT", "ARM_RESULT", "DEVELOPMENT_RESULT", "PLAN_RESULT"), "success"
        ) | {"VERIFIER_REQUIRED": "false", "VERIFIER_RESULT": "skipped"}

    def test_only_unchanged_skip_or_required_success_passes(self):
        ci.require_results(self.results)
        ci.require_results(self.results | {"VERIFIER_REQUIRED": "true", "VERIFIER_RESULT": "success"})

    def test_every_required_lane_must_succeed(self):
        for lane in ("CORE_RESULT", "ARM_RESULT", "DEVELOPMENT_RESULT", "PLAN_RESULT"):
            for result in ("failure", "cancelled", "skipped", ""):
                with self.subTest(lane=lane, result=result), self.assertRaises(ValueError):
                    ci.require_results(self.results | {lane: result})

    def test_selected_verifier_cannot_be_skipped_failed_or_cancelled(self):
        for result in ("skipped", "failure", "cancelled", ""):
            with self.subTest(result=result), self.assertRaises(ValueError):
                ci.require_results(self.results | {"VERIFIER_REQUIRED": "true", "VERIFIER_RESULT": result})

    def test_missing_plan_output_or_unexpected_result_blocks(self):
        for updates in ({"VERIFIER_REQUIRED": ""}, {"VERIFIER_REQUIRED": "maybe"},
                        {"VERIFIER_RESULT": "failure"}, {"VERIFIER_RESULT": "success"}):
            with self.subTest(updates=updates), self.assertRaises(ValueError):
                ci.require_results(self.results | updates)


if __name__ == "__main__":
    unittest.main()
