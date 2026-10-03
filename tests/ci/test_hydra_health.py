import importlib.util
import io
import os
from pathlib import Path
import sys
import unittest
from unittest.mock import patch
import urllib.error

SCRIPTS = Path(__file__).resolve().parents[2] / ".github/scripts"
sys.path.insert(0, str(SCRIPTS))
spec = importlib.util.spec_from_file_location("hydra_health", SCRIPTS / "hydra_health.py")
health = importlib.util.module_from_spec(spec)
spec.loader.exec_module(health)


def observation(healthy=False):
    return {"state": "up" if healthy else "down", "healthy": healthy,
            "observed_at": "2026-10-03T00:00:00+00:00", "source": health.HYDRA + "/queue-runner-status"}


def incident(number=42):
    return {"number": number, "title": health.TITLE, "body": health.MARKER + "\nincident",
            "user": {"login": "github-actions[bot]"}}


class HealthMonitorTests(unittest.TestCase):
    def test_transient_failure_recovers_without_an_incident(self):
        samples = iter((observation(), observation(), observation(True)))
        waits = []
        self.assertTrue(health.confirmed_probe(lambda: next(samples), waits.append)["healthy"])
        self.assertEqual(waits, [30, 30])
        waits.clear()
        self.assertTrue(health.confirmed_probe(lambda: observation(True), waits.append)["healthy"])
        self.assertEqual(waits, [])

    def test_persistent_failure_requires_three_observations(self):
        samples = []
        waits = []
        def check():
            samples.append(1)
            return observation()
        self.assertFalse(health.confirmed_probe(check, waits.append)["healthy"])
        self.assertEqual(len(samples), 3)
        self.assertEqual(waits, [30, 30])

    def test_probe_errors_are_bounded_and_contain_no_transport_details(self):
        with patch.object(health, "queue_health", side_effect=RuntimeError("private secret response")):
            result = health.probe()
        self.assertEqual(result["state"], "probe_unavailable")
        self.assertFalse(result["healthy"])
        self.assertNotIn("secret", str(result))

    def test_incident_creation_unchanged_failure_and_recovery(self):
        rows = []
        writes = []
        def request(path, method="GET", data=None):
            if method == "GET":
                return rows
            writes.append((path, method, data))
            if method == "POST":
                rows.append(incident())
            return {}
        self.assertEqual(health.reconcile(observation(), request), "incident_opened")
        self.assertEqual(len(writes), 1)
        self.assertEqual(writes[0][0:2], ("/issues", "POST"))
        self.assertTrue(writes[0][2]["body"].startswith(health.MARKER))
        self.assertEqual(health.reconcile(observation(), request), "incident_unchanged")
        self.assertEqual(len(writes), 1)
        self.assertEqual(health.reconcile(observation(True), request), "recovered")
        self.assertEqual(writes[-1], ("/issues/42", "PATCH", {"state": "closed", "state_reason": "completed"}))
        self.assertEqual(health.reconcile(observation(True), lambda _: []), "healthy")

    def test_only_its_own_bot_incident_can_be_closed(self):
        rows = [incident() | {"user": {"login": "human"}},
                incident() | {"body": "unrelated"}, incident() | {"title": "unrelated"},
                incident() | {"pull_request": {}}]
        writes = []
        def request(path, method="GET", data=None):
            if method == "GET":
                return rows
            writes.append((path, method, data))
        self.assertEqual(health.reconcile(observation(True), request), "healthy")
        self.assertEqual(writes, [])

    def test_invalid_duplicate_or_unbounded_inventory_cannot_mutate_issues(self):
        for rows in ([incident(), incident(43)], [incident(True)], [None],
                     [incident() | {"user": None}], {}):
            writes = []
            def request(path, method="GET", data=None):
                if method != "GET":
                    writes.append(path)
                return rows
            with self.subTest(rows=rows), self.assertRaises(ValueError):
                health.reconcile(observation(True), request)
            self.assertEqual(writes, [])
        calls = []
        def full_page(path, method="GET", data=None):
            calls.append(method)
            return [incident() | {"title": "unrelated"}] * 100
        with self.assertRaisesRegex(ValueError, "reviewed bound"):
            health.reconcile(observation(True), full_page)
        self.assertEqual(calls, ["GET"] * 10)

    def test_pagination_finds_an_existing_incident(self):
        pages = iter(([incident() | {"title": "unrelated"}] * 100, [incident()]))
        self.assertEqual(health.reconcile(observation(), lambda _: next(pages)), "incident_unchanged")


class IncidentTransportTests(unittest.TestCase):
    def test_only_reviewed_github_operations_carry_the_token(self):
        requests = []
        class Opener:
            def open(self, request, **kwargs):
                requests.append(request)
                return io.BytesIO(b"{}")
        with patch.dict(os.environ, {"GITHUB_TOKEN": "test_secret"}), patch.object(
            health.urllib.request, "build_opener", return_value=Opener()
        ):
            health.github("/issues?state=open&per_page=100&page=1")
            health.github("/issues", "POST", {"title": "incident"})
            health.github("/issues/42", "PATCH", {"state": "closed"})
            for path, method in (("https://example.test", "GET"), ("/issues/../escape", "PATCH"),
                                 ("/issues/42", "DELETE"), ("/issues/42", "POST"),
                                 ("/issues", "PATCH"), ("/issues", "GET")):
                with self.subTest(path=path, method=method), self.assertRaises(ValueError):
                    health.github(path, method)
        self.assertEqual(len(requests), 3)
        for request in requests:
            self.assertTrue(request.full_url.startswith(health.API + "/issues"))
            self.assertEqual(request.get_header("Authorization"), "Bearer test_secret")
        self.assertIsNone(health.NoRedirect().redirect_request(requests[0], None, 302, "", {}, "https://example.test"))

    def test_api_failures_and_oversized_responses_are_sanitized(self):
        class Opener:
            def open(self, request, **kwargs):
                return io.BytesIO(b"x" * (1024 * 1024 + 1))
        with patch.dict(os.environ, {"GITHUB_TOKEN": "test_secret"}), patch.object(
            health.urllib.request, "build_opener", return_value=Opener()
        ), self.assertRaisesRegex(RuntimeError, "incident API request failed"):
            health.github("/issues?state=open&per_page=100&page=1")
        failure = urllib.error.HTTPError(health.API, 403, "Forbidden", {}, io.BytesIO(b"secret response"))
        with patch.dict(os.environ, {"GITHUB_TOKEN": "test_secret"}), patch.object(
            health.urllib.request.OpenerDirector, "open", side_effect=failure
        ), self.assertRaises(RuntimeError) as error:
            health.github("/issues?state=open&per_page=100&page=1")
        self.assertNotIn("secret", str(error.exception))


if __name__ == "__main__":
    unittest.main()
