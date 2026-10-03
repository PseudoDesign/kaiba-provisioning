#!/usr/bin/env python3
"""Require Hydra results for this commit and the planned ARM64 derivations."""

import json
import os
from pathlib import Path
import re
import sys
import time
import urllib.error
import urllib.parse
import urllib.request

from verifier_ci import HEAVY_CHECKS


HYDRA = "https://hydra.pseudo.design"
REPOSITORY = "PseudoDesign/kaiba-provisioning"
CONTEXT = "ci/hydra/kaiba-provisioning/aarch64-linux."
API = f"https://api.github.com/repos/{REPOSITORY}"


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def get(url):
    headers = {"Accept": "application/json", "User-Agent": "kaiba-hydra-ci"}
    if url.startswith(API + "/"):
        headers["Authorization"] = "Bearer " + os.environ["GITHUB_TOKEN"]
        headers["X-GitHub-Api-Version"] = "2022-11-28"
    elif not url.startswith(HYDRA + "/"):
        raise ValueError("unexpected API origin")
    opener = urllib.request.build_opener(NoRedirect())
    try:
        with opener.open(urllib.request.Request(url, headers=headers), timeout=30) as response:
            return json.load(response)
    except urllib.error.HTTPError as error:
        if error.code == 404 and url.startswith(HYDRA + "/jobset/kaiba-provisioning/ci-"):
            return None
        # Never echo server response bodies, requests or authorization headers.
        raise RuntimeError(f"CI API request returned HTTP {error.code}") from None


def validate_expected(expected):
    if not isinstance(expected, dict) or set(expected) != set(HEAVY_CHECKS):
        raise ValueError("Hydra must cover exactly the ten planned ARM64 checks")
    for path in expected.values():
        if not isinstance(path, str) or not re.fullmatch(
            r"/nix/store/[0-9a-z]{32}-[A-Za-z0-9+._?=-]+\.drv", path
        ):
            raise ValueError("invalid expected derivation")


def statuses_for_commit(sha, request=get):
    if not re.fullmatch(r"[0-9a-f]{40}", sha):
        raise ValueError("a full commit SHA is required")
    latest = {}
    # GitHub returns newest first. Only the newest status for each context
    # counts; an older success must never override a newer failure or pending.
    for page in range(1, 11):
        statuses = request(f"{API}/commits/{sha}/statuses?per_page=100&page={page}")
        if not isinstance(statuses, list):
            raise ValueError("invalid GitHub status response")
        for status in statuses:
            context = status.get("context", "")
            if context.startswith(CONTEXT) and context.removeprefix(CONTEXT) in HEAVY_CHECKS:
                latest.setdefault(context.removeprefix(CONTEXT), status)
        if len(statuses) < 100 or len(latest) == len(HEAVY_CHECKS):
            break
    return latest


def completed_builds(statuses, expected, request=get):
    validate_expected(expected)
    for name, status in statuses.items():
        if status.get("state") in ("error", "failure"):
            raise RuntimeError(f"Hydra check failed: {name}")
    if set(statuses) != set(expected) or any(status.get("state") != "success" for status in statuses.values()):
        return None
    builds = []
    for name in HEAVY_CHECKS:
        target = statuses[name].get("target_url", "")
        match = re.fullmatch(re.escape(HYDRA) + r"/build/([1-9][0-9]*)", target)
        if not match:
            raise ValueError(f"unexpected Hydra build URL for {name}")
        build = request(target)
        identity = {"id": int(match[1]), "project": "kaiba-provisioning", "jobset": "main",
                    "job": "aarch64-linux." + name, "system": "aarch64-linux", "drvpath": expected[name]}
        if any(build.get(key) != value for key, value in identity.items()):
            raise ValueError(f"Hydra result does not match the planned derivation: {name}")
        if build.get("finished") != 1:
            return None
        if build.get("buildstatus") != 0:
            raise RuntimeError(f"Hydra build failed: {name}")
        builds.append((name, target))
    return builds


def run_jobset(environment):
    if environment.get("GITHUB_EVENT_NAME") not in {"pull_request", "workflow_dispatch"}:
        raise ValueError("only PR and manual runs use immutable run jobsets")
    values = [environment.get(key, "") for key in ("GITHUB_RUN_ID", "GITHUB_RUN_ATTEMPT")]
    if any(re.fullmatch(r"[1-9][0-9]*", value) is None for value in values):
        raise ValueError("a canonical workflow run ID and attempt are required")
    return "ci-" + "-".join(values)


def completed_evaluation(jobset, evaluations, expected, sha, name, request=get):
    validate_expected(expected)
    if not re.fullmatch(r"[0-9a-f]{40}", sha) or not re.fullmatch(r"ci-[1-9][0-9]*-[1-9][0-9]*", name):
        raise ValueError("invalid run revision or jobset")
    if jobset is None:
        return None
    flake = f"github:{REPOSITORY}/{sha}"
    identity = {"name": name, "project": "kaiba-provisioning", "type": 1, "flake": flake}
    if any(jobset.get(key) != value for key, value in identity.items()):
        raise ValueError("Hydra jobset does not match this exact run revision")
    if jobset.get("errormsg") or jobset.get("fetcherrormsg"):
        raise RuntimeError("Hydra run evaluation failed; inspect its jobset")
    if evaluations is None or not evaluations.get("evals"):
        return None
    rows = evaluations["evals"]
    if not isinstance(rows, list) or len(rows) != 1:
        raise ValueError("expected a single immutable run evaluation")
    evaluation = rows[0]
    reference = evaluation.get("flake", "")
    base, _, query = reference.partition("?")
    parameters = urllib.parse.parse_qs(query, strict_parsing=True)
    if base != flake or set(parameters) - {"narHash"}:
        raise ValueError("Hydra evaluation used a different source revision")
    ids = evaluation.get("builds")
    if (not isinstance(ids, list) or len(ids) != len(expected)
            or any(type(value) is not int or value <= 0 for value in ids)
            or len(set(ids)) != len(ids)):
        raise ValueError("Hydra evaluation must contain exactly ten distinct builds")
    completed = {}
    pending = False
    for build_id in ids:
        url = f"{HYDRA}/build/{build_id}"
        build = request(url)
        job = build.get("job", "").removeprefix("aarch64-linux.")
        if job not in expected or job in completed:
            raise ValueError("unexpected or duplicate job in Hydra evaluation")
        identity = {"id": build_id, "project": "kaiba-provisioning", "job": "aarch64-linux." + job,
                    "system": "aarch64-linux", "drvpath": expected[job]}
        if any(build.get(key) != value for key, value in identity.items()):
            raise ValueError(f"Hydra run result does not match the planned derivation: {job}")
        # A reused build may originate in another jobset. Membership in this
        # exact-commit evaluation, plus the planned drvPath, binds its result.
        if build.get("finished") != 1:
            pending = True
        elif build.get("buildstatus") != 0:
            raise RuntimeError(f"Hydra build failed: {job}")
        completed[job] = url
    return None if pending else [(job, completed[job]) for job in HEAVY_CHECKS]


def report(sha, builds):
    summary = f"### Hydra ARM64 checks\n\nCommit: `{sha}`\n\n"
    summary += "\n".join(f"- [{name}]({url}): passed" for name, url in builds) + "\n"
    with Path(os.environ["GITHUB_STEP_SUMMARY"]).open("a") as output:
        output.write(summary)
    print(f"All {len(builds)} Hydra checks match commit {sha}'s derivations")


def queue_health(request=get, now=None):
    """Observe availability only; this never establishes a passing build."""
    value = request(HYDRA + "/queue-runner-status")
    if (not isinstance(value, dict) or not isinstance(value.get("status"), str)
            or value["status"] not in {"up", "down", "unknown", "unreachable"}):
        raise ValueError("invalid Hydra queue-runner health response")
    state = value["status"]
    if state == "up":
        timestamp = value.get("time")
        now = time.time() if now is None else now
        if (type(timestamp) is not int or timestamp <= 0
                or timestamp > now + 60 or now - timestamp > 300):
            return "stale"
    return state


class PendingHealth:
    """Bound infrastructure waits without imposing a build-speed threshold."""
    def __init__(self):
        self.unhealthy_since = None
        self.phase = None
        self.phase_since = None

    def observe(self, now, state, phase):
        if state == "up":
            self.unhealthy_since = None
        elif self.unhealthy_since is None:
            self.unhealthy_since = now
        elif now - self.unhealthy_since >= 300:
            raise RuntimeError("Hydra queue runner unavailable for five minutes; "
                               "inspect Ace or restore the GitHub ARM backend")
        if phase != self.phase:
            self.phase, self.phase_since = phase, now
        elif phase != "builds" and now - self.phase_since >= 600:
            raise RuntimeError("Hydra " + phase + " absent for ten minutes; "
                               "inspect run discovery/evaluation before retrying")


def main():
    sha = os.environ["GITHUB_SHA"]
    expected = json.loads(os.environ["HYDRA_EXPECTED_DERIVATIONS"])
    validate_expected(expected)
    if not re.fullmatch(r"[0-9a-f]{40}", sha):
        raise ValueError("a full commit SHA is required")
    event = os.environ["GITHUB_EVENT_NAME"]
    name = None if event == "push" else run_jobset(os.environ)
    if event == "push" and os.environ.get("GITHUB_REF") != "refs/heads/main":
        raise ValueError("only main pushes use the main jobset")
    # Leave five minutes for checkout/cleanup within the six-hour job limit.
    deadline = time.monotonic() + 355 * 60
    pending_health = PendingHealth()
    while time.monotonic() < deadline:
        if name:
            path = f"{HYDRA}/jobset/kaiba-provisioning/{name}"
            jobset = get(path)
            evaluations = get(path + "/evals") if jobset is not None else None
            builds = completed_evaluation(jobset, evaluations, expected, sha, name)
            phase = "discovery" if jobset is None else (
                "evaluation" if not evaluations or not evaluations.get("evals") else "builds")
        else:
            statuses = statuses_for_commit(sha)
            builds = completed_builds(statuses, expected)
            phase = "evaluation" if not statuses else "builds"
        if builds is not None:
            report(sha, builds)
            return 0
        if not name and not statuses:
            head = get(API + "/git/ref/heads/main")
            if head.get("object", {}).get("sha") != sha:
                raise RuntimeError("main advanced before Hydra evaluated this commit; no success is assumed")
        health = queue_health()
        pending_health.observe(time.monotonic(), health, phase)
        print(f"Waiting for Hydra results for {sha} in {name or 'main'}; "
              f"phase={phase}, queue_runner={health}", flush=True)
        time.sleep(30)
    raise RuntimeError("timed out waiting for Hydra; missing results cannot pass CI")


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (OSError, ValueError, RuntimeError) as error:
        print(f"Hydra CI failed: {error}", file=sys.stderr)
        raise SystemExit(1)
