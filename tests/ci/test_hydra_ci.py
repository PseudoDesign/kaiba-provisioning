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


if __name__ == "__main__":
    unittest.main()
