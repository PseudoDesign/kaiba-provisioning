import importlib.util
import io
import json
import os
from pathlib import Path
import sys
import unittest
from unittest.mock import patch
import urllib.error

SCRIPTS = Path(__file__).resolve().parents[2] / ".github/scripts"
sys.path.insert(0, str(SCRIPTS))
spec = importlib.util.spec_from_file_location("hydra_ci", SCRIPTS / "hydra_ci.py")
ci = importlib.util.module_from_spec(spec)
spec.loader.exec_module(ci)
SHA = "a" * 40


def expected():
    return {name: f"/nix/store/{'b' * 32}-{name}.drv" for name in ci.HEAVY_CHECKS}


def statuses():
    return {name: {"state": "success", "context": ci.CONTEXT + name,
                   "target_url": f"{ci.HYDRA}/build/{index}"}
            for index, name in enumerate(ci.HEAVY_CHECKS, 1)}


def builds():
    return {f"{ci.HYDRA}/build/{index}": {
        "id": index, "project": "kaiba-provisioning", "jobset": "main",
        "job": "aarch64-linux." + name, "system": "aarch64-linux",
        "drvpath": path, "finished": 1, "buildstatus": 0,
    } for index, (name, path) in enumerate(expected().items(), 1)}


class HydraResultTests(unittest.TestCase):
    def test_all_ten_exact_derivations_are_required(self):
        result = ci.completed_builds(statuses(), expected(), builds().__getitem__)
        self.assertEqual(len(result), 10)
        missing = statuses()
        missing.pop(ci.HEAVY_CHECKS[0])
        self.assertIsNone(ci.completed_builds(missing, expected()))
        for wrong in ({}, expected() | {"unknown": "bad"}):
            with self.assertRaises(ValueError):
                ci.completed_builds(statuses(), wrong)

    def test_pending_failure_cancellation_and_wrong_build_cannot_pass(self):
        name = ci.HEAVY_CHECKS[0]
        pending = statuses()
        pending[name] = pending[name] | {"state": "pending"}
        self.assertIsNone(ci.completed_builds(pending, expected()))
        for state in ("error", "failure"):
            with self.assertRaises(RuntimeError):
                ci.completed_builds(pending | {name: pending[name] | {"state": state}}, expected())
        original = builds()
        url = statuses()[name]["target_url"]
        for change in ({"drvpath": "/nix/store/" + "c" * 32 + "-wrong.drv"},
                       {"system": "x86_64-linux"}, {"jobset": "other"},
                       {"project": "other"}, {"job": "aarch64-linux.other"}, {"id": 999}):
            response = original | {url: original[url] | change}
            with self.subTest(change=change), self.assertRaises(ValueError):
                ci.completed_builds(statuses(), expected(), response.__getitem__)
        for code in (1, 2, 3, 4, 8, 10, 11):
            response = original | {url: original[url] | {"buildstatus": code}}
            with self.subTest(code=code), self.assertRaises(RuntimeError):
                ci.completed_builds(statuses(), expected(), response.__getitem__)

    def test_newer_failure_wins_over_old_success_and_commit_is_exact(self):
        name = ci.HEAVY_CHECKS[0]
        data = [{"context": ci.CONTEXT + name, "state": "failure"},
                {"context": ci.CONTEXT + name, "state": "success"}]
        urls = []

        def request(url):
            urls.append(url)
            return data

        selected = ci.statuses_for_commit(SHA, request)
        self.assertEqual(selected[name]["state"], "failure")
        self.assertIn(f"/commits/{SHA}/statuses?", urls[0])
        for sha in ("main", "../escape", "a" * 39):
            with self.assertRaises(ValueError):
                ci.statuses_for_commit(sha, request)

    def test_status_pagination_and_wrong_hydra_origin(self):
        first = [{"context": "unrelated", "state": "success"}] * 100
        pages = iter((first, list(statuses().values())))
        selected = ci.statuses_for_commit(SHA, lambda url: next(pages))
        self.assertEqual(set(selected), set(ci.HEAVY_CHECKS))
        name = ci.HEAVY_CHECKS[0]
        for target in ("https://example.test/build/1", ci.HYDRA + ".evil.test/build/1",
                       ci.HYDRA + "/build/1?override=1"):
            selected = statuses()
            selected[name] = selected[name] | {"target_url": target}
            with self.assertRaises(ValueError):
                ci.completed_builds(selected, expected())

    def test_credentials_only_go_to_github_and_redirects_are_refused(self):
        class Response(io.BytesIO):
            pass

        requests = []

        class Opener:
            def open(self, request, **kwargs):
                requests.append(request)
                return Response(b"{}")

        with patch.dict(os.environ, {"GITHUB_TOKEN": "test_secret"}), patch.object(
            ci.urllib.request, "build_opener", return_value=Opener()
        ):
            ci.get(ci.API + "/commits/" + SHA + "/statuses")
            ci.get(ci.HYDRA + "/build/1")
            with self.assertRaises(ValueError):
                ci.get("https://api.github.com.evil.test/repos/x")
        self.assertEqual(requests[0].get_header("Authorization"), "Bearer test_secret")
        self.assertIsNone(requests[1].get_header("Authorization"))
        self.assertIsNone(ci.NoRedirect().redirect_request(requests[0], None, 302, "", {}, "https://example.test"))

    def test_api_errors_do_not_echo_response_or_token(self):
        failure = urllib.error.HTTPError(ci.API, 403, "Forbidden", {}, io.BytesIO(b"secret response"))
        with patch.dict(os.environ, {"GITHUB_TOKEN": "test_secret"}), patch.object(
            ci.urllib.request.OpenerDirector, "open", side_effect=failure
        ), self.assertRaisesRegex(RuntimeError, "HTTP 403") as error:
            ci.get(ci.API + "/commits/" + SHA + "/statuses")
        self.assertNotIn("secret", str(error.exception))


class RunEvaluationTests(unittest.TestCase):
    def setUp(self):
        self.name = "ci-42-2"
        self.jobset = {"project": "kaiba-provisioning", "name": self.name, "type": 1,
                       "flake": f"github:{ci.REPOSITORY}/{SHA}", "errormsg": "", "fetcherrormsg": ""}
        self.evaluation = {"id": 123, "flake": self.jobset["flake"] + "?narHash=sha256-test",
                           "builds": list(range(1, 11))}

    def result(self, jobset=None, evaluation=None, responses=None):
        return ci.completed_evaluation(
            self.jobset if jobset is None else jobset,
            {"evals": [self.evaluation if evaluation is None else evaluation]}, expected(), SHA,
            self.name, (builds() if responses is None else responses).__getitem__)

    def test_exact_run_evaluation_can_reuse_builds_from_main(self):
        self.assertEqual(len(self.result()), 10)
        self.assertIsNone(ci.completed_evaluation(None, None, expected(), SHA, self.name))
        self.assertIsNone(ci.completed_evaluation(self.jobset, {"evals": []}, expected(), SHA, self.name))

    def test_wrong_commit_run_attempt_or_evaluation_cannot_pass(self):
        for change in ({"flake": f"github:{ci.REPOSITORY}/main"}, {"name": "ci-42-1"},
                       {"project": "other"}, {"type": 0}):
            with self.subTest(change=change), self.assertRaises(ValueError):
                self.result(jobset=self.jobset | change)
        for change in ({"flake": f"github:{ci.REPOSITORY}/{'c' * 40}"},
                       {"flake": self.jobset["flake"] + "?dir=other"},
                       {"builds": list(range(1, 10))}, {"builds": [1] * 10},
                       {"builds": list(range(1, 10)) + [True]}):
            with self.subTest(change=change), self.assertRaises(ValueError):
                self.result(evaluation=self.evaluation | change)
        with self.assertRaises(ValueError):
            ci.completed_evaluation(self.jobset, {"evals": [self.evaluation] * 2}, expected(), SHA, self.name)

    def test_evaluation_build_failures_and_pending_are_not_success(self):
        for key in ("errormsg", "fetcherrormsg"):
            with self.assertRaises(RuntimeError):
                self.result(jobset=self.jobset | {key: "failed"})
        url = f"{ci.HYDRA}/build/1"
        original = builds()
        self.assertIsNone(self.result(responses=original | {url: original[url] | {"finished": 0}}))
        for code in (1, 2, 3, 4, 8, 10, 11):
            with self.assertRaises(RuntimeError):
                self.result(responses=original | {url: original[url] | {"buildstatus": code}})
        for change in ({"drvpath": "/nix/store/" + "d" * 32 + "-wrong.drv"}, {"system": "x86_64-linux"},
                       {"job": "aarch64-linux.other"}, {"id": 999}, {"project": "other"}):
            with self.assertRaises(ValueError):
                self.result(responses=original | {url: original[url] | change})

    def test_run_identity_is_attempt_specific_and_canonical(self):
        env = {"GITHUB_EVENT_NAME": "pull_request", "GITHUB_RUN_ID": "42", "GITHUB_RUN_ATTEMPT": "2"}
        self.assertEqual(ci.run_jobset(env), self.name)
        self.assertEqual(ci.run_jobset(env | {"GITHUB_EVENT_NAME": "workflow_dispatch"}), self.name)
        for change in ({"GITHUB_RUN_ID": "../42"}, {"GITHUB_RUN_ATTEMPT": "0"},
                       {"GITHUB_RUN_ID": "042"}, {"GITHUB_EVENT_NAME": "pull_request_target"}):
            with self.assertRaises(ValueError):
                ci.run_jobset(env | change)


class QueueHealthTests(unittest.TestCase):
    def test_health_requires_a_fresh_valid_timestamp(self):
        for state in ("down", "unknown", "unreachable"):
            self.assertEqual(ci.queue_health(lambda _: {"status": state}, now=1000), state)
        self.assertEqual(ci.queue_health(lambda _: {"status": "up", "time": 700}, now=1000), "up")
        for timestamp in (None, True, "1000", 0, 699, 1061):
            with self.subTest(timestamp=timestamp):
                self.assertEqual(ci.queue_health(lambda _: {"status": "up", "time": timestamp}, now=1000), "stale")
        for value in (None, [], {}, {"status": []}, {"status": "other"}):
            with self.subTest(value=value), self.assertRaises(ValueError):
                ci.queue_health(lambda _: value, now=1000)

    def test_unhealthy_grace_resets_on_recovery(self):
        health = ci.PendingHealth()
        health.observe(0, "down", "builds")
        health.observe(299, "stale", "builds")
        health.observe(300, "up", "builds")
        health.observe(301, "down", "builds")
        health.observe(600, "unknown", "builds")
        with self.assertRaisesRegex(RuntimeError, "queue runner unavailable"):
            health.observe(601, "down", "builds")

    def test_missing_discovery_and_evaluation_fail_early_but_builds_can_wait(self):
        for phase in ("discovery", "evaluation"):
            health = ci.PendingHealth()
            health.observe(0, "up", phase)
            health.observe(599, "up", phase)
            with self.subTest(phase=phase), self.assertRaisesRegex(RuntimeError, phase + " absent"):
                health.observe(600, "up", phase)
        health = ci.PendingHealth()
        health.observe(0, "up", "discovery")
        health.observe(599, "up", "evaluation")
        health.observe(1198, "up", "evaluation")
        health.observe(1199, "up", "builds")
        health.observe(20000, "up", "builds")

    def test_complete_validated_results_do_not_depend_on_queue_health(self):
        env = {"GITHUB_SHA": SHA, "HYDRA_EXPECTED_DERIVATIONS": json.dumps(expected()),
               "GITHUB_EVENT_NAME": "push", "GITHUB_REF": "refs/heads/main"}
        with patch.dict(os.environ, env), patch.object(ci, "statuses_for_commit", return_value=statuses()), patch.object(
            ci, "completed_builds", return_value=[("validated", "url")]
        ) as validation, patch.object(ci, "queue_health") as health, patch.object(ci, "report") as report:
            self.assertEqual(ci.main(), 0)
        validation.assert_called_once_with(statuses(), expected())
        health.assert_not_called()
        report.assert_called_once_with(SHA, [("validated", "url")])


if __name__ == "__main__":
    unittest.main()
