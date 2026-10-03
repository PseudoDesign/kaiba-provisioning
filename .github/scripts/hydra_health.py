#!/usr/bin/env python3
"""Report public Hydra availability and deduplicate one GitHub incident issue."""

import argparse
import datetime
import json
import os
import re
import sys
import time
import urllib.request

from hydra_ci import API, HYDRA, NoRedirect, queue_health

MARKER = "<!-- kaiba-hydra-health:v1 -->"
TITLE = "Hydra queue runner unavailable"


def probe():
    try:
        state = queue_health()
    except (OSError, ValueError, RuntimeError):
        # Server response bodies, transport details and credentials stay private.
        state = "probe_unavailable"
    return {"schema_version": "kaiba.ci.hydra-health/v1alpha1",
            "observed_at": datetime.datetime.now(datetime.timezone.utc).isoformat(),
            "state": state, "healthy": state == "up",
            "source": HYDRA + "/queue-runner-status"}


def confirmed_probe(check=probe, sleep=time.sleep):
    result = check()
    for _ in range(2):
        if result["healthy"]:
            break
        sleep(30)
        result = check()
    return result


def github(path, method="GET", data=None):
    if not re.fullmatch(r"/issues(?:/[1-9][0-9]*|\?state=open&per_page=100&page=[1-9][0-9]*)?", path):
        raise ValueError("unexpected incident API path")
    if ((method == "GET" and "?state=open&" not in path)
            or (method == "POST" and path != "/issues")
            or (method == "PATCH" and not re.fullmatch(r"/issues/[1-9][0-9]*", path))
            or method not in {"GET", "POST", "PATCH"}):
        raise ValueError("unexpected incident API operation")
    token = os.environ.get("GITHUB_TOKEN")
    if not token:
        raise ValueError("incident reporting requires its scoped GitHub token")
    body = None if data is None else json.dumps(data).encode()
    request = urllib.request.Request(API + path, data=body, method=method, headers={
        "Accept": "application/vnd.github+json", "Authorization": "Bearer " + token,
        "X-GitHub-Api-Version": "2022-11-28", "Content-Type": "application/json",
        "User-Agent": "kaiba-hydra-health"})
    try:
        opener = urllib.request.build_opener(NoRedirect())
        with opener.open(request, timeout=30) as response:
            raw = response.read(1024 * 1024 + 1)
        if len(raw) > 1024 * 1024:
            raise ValueError("incident response too large")
        return json.loads(raw)
    except (OSError, ValueError):
        raise RuntimeError("incident API request failed") from None


def reconcile(result, request=github):
    existing = []
    for page in range(1, 11):
        rows = request(f"/issues?state=open&per_page=100&page={page}")
        if not isinstance(rows, list):
            raise ValueError("invalid incident list")
        for row in rows:
            if not isinstance(row, dict) or not isinstance(row.get("user"), dict):
                raise ValueError("invalid incident record")
            if ("pull_request" not in row and row.get("title") == TITLE
                    and str(row.get("body", "")).startswith(MARKER)
                    and row.get("user", {}).get("login") == "github-actions[bot]"):
                if type(row.get("number")) is not int or row["number"] <= 0:
                    raise ValueError("invalid incident identity")
                existing.append(row["number"])
        if len(rows) < 100:
            break
    else:
        raise ValueError("incident list exceeds reviewed bound")
    if len(existing) > 1:
        raise ValueError("multiple active Hydra incidents require reconciliation")
    if result["healthy"]:
        if not existing:
            return "healthy"
        request(f"/issues/{existing[0]}", "PATCH", {"state": "closed", "state_reason": "completed"})
        return "recovered"
    if existing:
        return "incident_unchanged"
    body = (MARKER + "\nThe public Hydra queue-runner health check failed three probes "
            "over one minute.\n\nState: `" + result["state"] + "`\n\nObserved at: "
            + result["observed_at"] + "\n\n[Scheduler status](" + result["source"]
            + ") · [Build queue](" + HYDRA + "/queue)\n\nInspect Ace's queue-runner "
            "journal and disk reserve before restarting it. The documented rollback "
            "is to disable HYDRA_CI_ENABLED/HYDRA_MAIN_ENABLED and rerun complete CI "
            "workflows on GitHub ARM. Health never establishes passing build evidence.\n\n"
            "This incident is retained while the failure persists and closes after "
            "a fresh healthy observation; unchanged polls add no comments.")
    request("/issues", "POST", {"title": TITLE, "body": body})
    return "incident_opened"


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--alert", action="store_true")
    args = parser.parse_args()
    result = confirmed_probe() if args.alert else probe()
    if args.alert:
        result["incident_action"] = reconcile(result)
    print(json.dumps(result, sort_keys=True))
    return 0 if args.alert or result["healthy"] else 1


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (OSError, ValueError, RuntimeError):
        print("Hydra health reporting failed; inspect the scoped monitor configuration", file=sys.stderr)
        raise SystemExit(1)
