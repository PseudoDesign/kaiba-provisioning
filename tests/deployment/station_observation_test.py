#!/usr/bin/env python3
"""Exercise the packaged read-only station against a disposable mTLS authority.

Only the fixture setup sends create/claim/bind commands. No hardware, audit,
signing service, systemd unit, or existing authority state is used.
"""

import argparse
import contextlib
import json
import os
from pathlib import Path
import socket
import ssl
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.request


SCHEMA = "provisioning.kaiba.network/"
TRANSACTION_ID = "station-observation-integration"
OPERATIONS = [
    "program_customer_key_and_eeprom",
    "cold_power_cycle",
    "owned_readback",
    "test_owned_recovery",
    "post_recovery_readback",
    "test_negative_boot",
    "test_root_integrity",
]


def digest(character):
    return "sha256:" + character * 64


def require(condition, message):
    if not condition:
        raise AssertionError(message)


def request_json(url, *, tls=None, body=None, headers=None, expected_status=200):
    request_headers = dict(headers or {})
    if body is not None:
        request_headers["Content-Type"] = "application/json"
    request = urllib.request.Request(
        url,
        data=None if body is None else json.dumps(body).encode(),
        headers=request_headers,
    )
    # The check must use its local listeners even in shells with proxy settings.
    opener = urllib.request.build_opener(
        urllib.request.ProxyHandler({}), urllib.request.HTTPSHandler(context=tls)
    )
    try:
        response = opener.open(request, timeout=10)
    except urllib.error.HTTPError as error:
        response = error
    with response:
        payload = response.read()
        require(
            response.code == expected_status,
            f"{request.get_method()} {url}: HTTP {response.code}, expected "
            f"{expected_status}: {payload.decode(errors='replace')}",
        )
        return json.loads(payload)


def wait_ready(url, process, *, tls=None):
    deadline = time.monotonic() + 20
    last_error = None
    while time.monotonic() < deadline:
        require(process.poll() is None, f"listener exited with {process.returncode}")
        try:
            return request_json(url, tls=tls)
        except (OSError, urllib.error.URLError) as error:
            last_error = error
            time.sleep(0.05)
    raise AssertionError(f"listener did not become ready: {last_error}")


def stop(process):
    if process is None or process.poll() is not None:
        return
    process.terminate()
    try:
        process.wait(timeout=10)
    except subprocess.TimeoutExpired:
        process.kill()
        process.wait(timeout=5)


def run(deployment, station, directory):
    config_path = deployment / "share/kaiba/ubuntu-provisioning-authority/deployment.conf"
    config = dict(line.split("=", 1) for line in config_path.read_text().splitlines())
    require(config["LISTEN_ADDRESS"] == "127.0.0.1", "deployment must use loopback")
    station_parts = config["STATION_URI"].split("/")
    station_id, lane_id = station_parts[-3], station_parts[-1]
    pki = directory / "pki"
    subprocess.run(
        [deployment / "bin/kaiba-provision-authority-development-pki", "--output", pki],
        check=True,
        timeout=90,
    )
    state_path = directory / "control.json"
    control_url = f"https://127.0.0.1:{config['CONTROL_PORT']}"
    station_credentials = pki / "station/bridge"
    tls = ssl.create_default_context(cafile=station_credentials / "control-server-ca.crt")
    tls.minimum_version = ssl.TLSVersion.TLSv1_3
    tls.load_cert_chain(
        station_credentials / "station-client.crt",
        station_credentials / "station-client.key",
    )
    with socket.socket() as listener:
        listener.bind(("127.0.0.1", 0))
        station_address = f"127.0.0.1:{listener.getsockname()[1]}"
    station_url = "http://" + station_address
    control_args = [
        Path(config["CONTROL_PACKAGE"]) / "bin/kaiba-provision-control",
        "--listen", f"127.0.0.1:{config['CONTROL_PORT']}",
        "--state", state_path,
        "--tls-cert", pki / "authority/control-server.crt",
        "--tls-key", pki / "authority/control-server.key",
        "--client-ca", pki / "authority/client-ca.crt",
    ]
    station_args = [
        station,
        "--listen", station_address,
        "--station-id", station_id,
        "--lane-id", lane_id,
        "--transaction-id", TRANSACTION_ID,
        "--control-url", control_url,
        "--tls-cert", station_credentials / "station-client.crt",
        "--tls-key", station_credentials / "station-client.key",
        "--control-server-ca", station_credentials / "control-server-ca.crt",
        # Missing local paths demonstrate that recorded identity is independent
        # of a local physical observation. No device path is opened for I/O.
        "--rpiboot-sysfs", directory / "absent-usb",
        "--uart", directory / "absent-uart",
    ]
    control_process = station_process = None
    with contextlib.ExitStack() as stack:
        control_log = stack.enter_context((directory / "control.log").open("ab"))
        station_log = stack.enter_context((directory / "station.log").open("ab"))

        def start_control():
            process = subprocess.Popen(control_args, stdout=control_log, stderr=subprocess.STDOUT)
            stack.callback(stop, process)
            wait_ready(control_url + "/healthz", process, tls=tls)
            return process

        def start_station():
            process = subprocess.Popen(station_args, stdout=station_log, stderr=subprocess.STDOUT)
            stack.callback(stop, process)
            runtime = wait_ready(station_url + "/runtime-config.json", process)
            require(runtime["read_only"] is True, "station runtime is not read-only")
            require(runtime["enrollment_capable"] is False, "viewer claims enrollment capability")
            require("action_endpoint" not in runtime, "viewer advertises an action endpoint")
            return process

        def command(operation, version, **fields):
            return request_json(
                control_url + "/api/v1/commands",
                tls=tls,
                body={
                    "schema_version": SCHEMA + "control-command/v1alpha1",
                    "operation": operation,
                    "request": {
                        "schema_version": SCHEMA + version,
                        "idempotency_key": "fixture-" + operation,
                        "transaction_id": TRANSACTION_ID,
                        **fields,
                    },
                },
            )

        control_process = start_control()
        transaction = command(
            "create_transaction", "create-transaction-request/v1alpha3",
            asset_id="disposable-test-asset", intended_logical_id="not-an-enrolled-device",
            profile_id="raspberry-pi-5-model-b-v1alpha1",
            bundle_digest=digest("1"), policy_digest=digest("2"),
            expected_prestate_customer_key_hash=digest("0"),
            expected_customer_key_hash=digest("3"),
        )
        transaction = command(
            "acquire_claim", "acquire-claim-request/v1alpha1",
            expected_resource_version=transaction["resource_version"],
            station_id=station_id, lane_id=lane_id, mode="mutation",
            allowed_stages=OPERATIONS, lease_duration_seconds=3600,
        )
        transaction = command(
            "bind_target", "bind-target-request/v1alpha1",
            expected_resource_version=transaction["resource_version"],
            claim_id=transaction["active_claim"]["id"], fence_epoch=transaction["fence_epoch"],
            target_fingerprint=digest("4"), observation_digest=digest("5"),
            customer_key_hash=digest("0"),
        )
        baseline_bytes = state_path.read_bytes()
        baseline_stat = state_path.stat()

        def unchanged():
            require(state_path.read_bytes() == baseline_bytes, "viewer changed authority state")
            stat = state_path.stat()
            require(
                (stat.st_ino, stat.st_mtime_ns) == (baseline_stat.st_ino, baseline_stat.st_mtime_ns),
                "viewer rewrote authority state",
            )

        def current():
            state = request_json(station_url + "/api/v1/state")
            require(state["read_status"] == "current" and not state["stale"], "read is not current")
            snapshot = state["snapshot"]
            require(snapshot["id"] == TRANSACTION_ID, "wrong transaction")
            require(snapshot["status"] == "target_bound", "recorded status changed")
            require(snapshot["resource_version"] == transaction["resource_version"], "wrong version")
            require(snapshot["recorded_prestate"]["fingerprint"] == digest("4"), "target binding lost")
            require(snapshot["evidence_basis"] == "coordinator_recorded", "wrong evidence basis")
            require(snapshot["fleet_admission"] == "unevaluated", "viewer claims fleet admission")
            require("allowed_actions" not in state, "viewer advertises workflow actions")
            require(state["last_successful_read"], "successful read time missing")
            unchanged()
            return state

        station_process = start_station()
        first = current()
        request_json(
            station_url + "/api/v1/actions",
            body={"action": "create_transaction", "expected_revision": 1},
            headers={"Origin": station_url}, expected_status=403,
        )
        unchanged()
        stop(station_process)
        station_process = start_station()
        restarted = current()
        require(restarted["snapshot"] == first["snapshot"], "station restart lost the recorded result")

        stop(control_process)
        unavailable = request_json(station_url + "/api/v1/state")
        require(unavailable["read_status"] == "unavailable", "outage is not reported")
        require(unavailable["stale"] is True, "retained outage snapshot is not marked stale")
        require(unavailable["snapshot"] == restarted["snapshot"], "outage discarded the last snapshot")
        require(
            unavailable["last_successful_read"] == restarted["last_successful_read"],
            "failed read advanced the successful-read time",
        )
        unchanged()
        control_process = start_control()
        recovered = current()
        require(recovered["snapshot"] == first["snapshot"], "authority restart changed the recorded result")
        persisted = request_json(control_url + "/api/v1/transactions/" + TRANSACTION_ID, tls=tls)
        require(persisted == transaction, "authority transaction changed during observation")
        unchanged()

        # A fresh viewer cannot invent an earlier successful read during outage.
        stop(control_process)
        stop(station_process)
        station_process = start_station()
        empty = request_json(station_url + "/api/v1/state")
        require(empty["read_status"] == "unavailable", "fresh viewer hid authority outage")
        require("snapshot" not in empty and "last_successful_read" not in empty, "fresh viewer invented data")
        unchanged()
        control_process = start_control()
        current()
    print("station observation integration: read, restarts, outage/recovery, and read-only boundary passed")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--deployment", type=Path, required=True)
    parser.add_argument("--station", type=Path, required=True)
    arguments = parser.parse_args()
    os.umask(0o077)
    with tempfile.TemporaryDirectory(prefix="kaiba-station-observation-") as temporary:
        directory = Path(temporary)
        try:
            run(arguments.deployment, arguments.station, directory)
        except Exception:
            for name in ("control.log", "station.log"):
                path = directory / name
                if path.exists():
                    print(f"{name}:\n{path.read_text(errors='replace')}", file=sys.stderr)
            raise


if __name__ == "__main__":
    main()
