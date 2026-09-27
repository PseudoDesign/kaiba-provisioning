#!/usr/bin/env python3
"""Require Hydra results for this commit and the planned ARM64 derivations."""

import json
import os
from pathlib import Path
import re
import sys
import time
import urllib.error
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


def main():
    sha = os.environ["GITHUB_SHA"]
    expected = json.loads(os.environ["HYDRA_EXPECTED_DERIVATIONS"])
    validate_expected(expected)
    deadline = time.monotonic() + 235 * 60
    while time.monotonic() < deadline:
        statuses = statuses_for_commit(sha)
        builds = completed_builds(statuses, expected)
        if builds is not None:
            summary = f"### Hydra ARM64 checks\n\nCommit: `{sha}`\n\n"
            summary += "\n".join(f"- [{name}]({url}): passed" for name, url in builds) + "\n"
            with Path(os.environ["GITHUB_STEP_SUMMARY"]).open("a") as output:
                output.write(summary)
            print(f"All {len(builds)} Hydra checks match commit {sha}'s derivations")
            return 0
        if not statuses:
            head = get(API + "/git/ref/heads/main")
            if head.get("object", {}).get("sha") != sha:
                raise RuntimeError("main advanced before Hydra evaluated this commit; no success is assumed")
        print(f"Waiting for Hydra results for {sha}: {len(statuses)}/{len(expected)} contexts", flush=True)
        time.sleep(30)
    raise RuntimeError("timed out waiting for Hydra; missing results cannot pass CI")


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (OSError, ValueError, RuntimeError) as error:
        print(f"Hydra CI failed: {error}", file=sys.stderr)
        raise SystemExit(1)
