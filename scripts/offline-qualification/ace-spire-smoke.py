"""Temporary non-root Ace SPIRE smoke. No deployment or privileged operations."""
import argparse
import datetime
import hashlib
import json
import os
import pathlib
import platform
import re
import shutil
import signal
import socket
import subprocess
import tempfile
import time


class Stopped(Exception):
    pass


def stop_signal(number, _frame):
    raise Stopped("signal-" + str(number))


def require(condition, code):
    if not condition:
        raise Stopped(code)


def terminate(process):
    if process.poll() is None:
        process.terminate()
        try:
            process.wait(timeout=5)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait(timeout=5)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--probe", required=True)
    parser.add_argument("--probe-sha256", required=True)
    args = parser.parse_args()
    report = {"schema": "kaiba.ace-spire-smoke/v1alpha1", "synthetic": True,
              "hardware_qualified": False, "boot_chain_authenticated": False,
              "offline_rollback_qualified": False, "clock_continuity_qualified": False,
              "fleet_admission": "unevaluated", "publication_authorized": False,
              "checks": [], "passed": False, "cleanup_complete": False}
    children, logs = [], []
    state = None
    for sig in (signal.SIGINT, signal.SIGTERM, signal.SIGHUP, signal.SIGALRM):
        signal.signal(sig, stop_signal)
    signal.alarm(240)
    os.umask(0o077)

    def run(argv, timeout=10, success=True):
        process = subprocess.Popen(argv, stdin=subprocess.DEVNULL,
                                   stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        children.append(process)
        out, err = process.communicate(timeout=timeout)
        require(len(out) <= 65536 and len(err) <= 65536, "oversized-command-output")
        if success:
            require(process.returncode == 0, "command-failed:" + pathlib.Path(argv[0]).name)
        return process.returncode, out, err, process.pid

    try:
        require(os.geteuid() != 0, "must-run-as-existing-nonroot-user")
        require(platform.machine() == "aarch64", "wrong-architecture")
        require(socket.gethostname().split(".")[0] == "ace", "wrong-host")
        expected_system = "/nix/store/f4q82s6kzy6y4q943y9v9nsm64c9s0xp-nixos-system-ace-26.05.20260807.ee48b14"
        require(os.path.realpath("/run/current-system") == expected_system, "running-system-changed-since-inventory")
        require(re.fullmatch(r"[0-9a-f]{64}", args.probe_sha256), "invalid-probe-digest")
        probe = str(pathlib.Path(args.probe).resolve(strict=True))
        require(hashlib.sha256(pathlib.Path(probe).read_bytes()).hexdigest() == args.probe_sha256, "probe-digest-mismatch")
        server = "/nix/store/amkjv23s9r9wjxy7kydahb3axi01ri80-spire-1.15.2-server/bin/spire-server"
        agent = "/nix/store/xprm29ibxp2g3s4j2p1n075gp18n21lv-spire-1.15.2-agent/bin/spire-agent"
        for binary in (server, agent):
            _, version_out, version_err, _ = run([binary, "--version"])
            require((version_out + version_err).strip() == b"1.15.2", "wrong-spire-version")
        report.update(architecture="aarch64", running_system=expected_system,
                      spire_version="1.15.2", probe_sha256=args.probe_sha256)
        state = pathlib.Path(tempfile.mkdtemp(prefix="kaiba-ace-spire-", dir="/tmp"))
        for directory in ("server", "agent", "sockets"):
            (state / directory).mkdir(mode=0o700)
        admin, api = state / "sockets/admin.sock", state / "sockets/workload.sock"
        # An ephemeral loopback port avoids pre-existing services. A bind race
        # causes this server to fail; the script never stops a conflicting peer.
        with socket.socket() as reservation:
            reservation.bind(("127.0.0.1", 0))
            port = reservation.getsockname()[1]
        domain = "ace-smoke.test"
        parent = "spiffe://ace-smoke.test/node/temporary-agent"
        workload = "spiffe://ace-smoke.test/device/ace-smoke/instance/temporary/workload/rotation-probe"
        (state / "server.conf").write_text(f'''server {{
  bind_address = "127.0.0.1"
  bind_port = {port}
  socket_path = "{admin}"
  trust_domain = "{domain}"
  data_dir = "{state}/server"
  default_x509_svid_ttl = "60s"
  agent_ttl = "1h"
  log_level = "WARN"
  audit_log_enabled = false
}}
plugins {{
  KeyManager "disk" {{ plugin_data {{ keys_path = "{state}/server/keys.json" }} }}
  DataStore "sql" {{ plugin_data {{ database_type = "sqlite3" connection_string = "{state}/server/data.sqlite3" }} }}
  NodeAttestor "join_token" {{ plugin_data {{ }} }}
}}
''')

        def start(binary, config, logname):
            log = open(state / logname, "ab", buffering=0)
            logs.append(log)
            child = subprocess.Popen([binary, "run", "-config", str(state / config)],
                                     stdin=subprocess.DEVNULL, stdout=log, stderr=log)
            children.append(child)
            return child

        def ready(binary, endpoint, child):
            deadline = time.monotonic() + 45
            while time.monotonic() < deadline:
                require(child.poll() is None, "spire-process-exited")
                if run([binary, "healthcheck", "-socketPath", str(endpoint)], success=False)[0] == 0:
                    return
                time.sleep(0.5)
            raise Stopped("spire-readiness-timeout")

        server_process = start(server, "server.conf", "server.log")
        ready(server, admin, server_process)
        token_response = run([server, "token", "generate", "-socketPath", str(admin),
                              "-ttl", "180", "-spiffeID", parent, "-output", "json"])[1]
        (state / "join-token").write_text(json.loads(token_response)["value"])
        del token_response
        (state / "bundle.pem").write_bytes(run([server, "bundle", "show", "-socketPath", str(admin)])[1])

        def agent_config(token_file):
            (state / "agent.conf").write_text(f'''agent {{
  data_dir = "{state}/agent"
  socket_path = "{api}"
  trust_domain = "{domain}"
  server_address = "127.0.0.1"
  server_port = {port}
  trust_bundle_path = "{state}/bundle.pem"
  join_token_file = "{token_file}"
  rebootstrap_mode = "never"
  log_level = "WARN"
}}
plugins {{
  KeyManager "disk" {{ plugin_data {{ directory = "{state}/agent/keys" }} }}
  NodeAttestor "join_token" {{ plugin_data {{ }} }}
  WorkloadAttestor "unix" {{ plugin_data {{ }} }}
}}
''')

        agent_config(state / "join-token")
        agent_process = start(agent, "agent.conf", "agent.log")
        ready(agent, api, agent_process)
        # The temporary same-UID selector is a smoke fixture. It establishes
        # no service-user isolation and grants no production membership.
        run([server, "entry", "create", "-socketPath", str(admin), "-parentID", parent,
             "-spiffeID", workload, "-selector", "unix:uid:" + str(os.getuid()), "-x509SVIDTTL", "60"])
        result = run([probe, "fetch", "--socket", "unix://" + str(api),
                      "--count", "2", "--timeout", "100s"], timeout=105)[1]
        identities = [json.loads(line) for line in result.splitlines()]
        require(len(identities) == 2 and all(x["spiffe_id"] == workload for x in identities), "unexpected-workload-identity")
        require(identities[0]["serial"] != identities[1]["serial"] and identities[0]["pid"] == identities[1]["pid"], "live-source-did-not-rotate")
        require(agent_process.poll() is None and server_process.poll() is None, "identity-process-exited-during-rotation")
        report["checks"].append("same-probe-process-observed-distinct-SVID-serials")
        report["rotation"] = identities
        (state / "join-token").unlink()
        terminate(agent_process)
        agent_config("")
        agent_process = start(agent, "agent.conf", "agent.log")
        ready(agent, api, agent_process)
        cached = json.loads(run([probe, "fetch", "--socket", "unix://" + str(api), "--timeout", "15s"], timeout=20)[1])
        require(cached["spiffe_id"] == workload, "restart-changed-identity")
        report["checks"].append("agent-restarted-from-private-state-with-consumed-grant-removed")
        terminate(server_process)
        expires = datetime.datetime.fromisoformat(cached["not_after"].replace("Z", "+00:00")).timestamp()
        require(0 < expires - time.time() <= 65, "unexpected-credential-lifetime")
        while time.time() <= expires + 1:
            require(agent_process.poll() is None, "agent-exited-during-authority-outage")
            time.sleep(0.5)
        offset = (state / "agent.log").stat().st_size
        code, _, diagnostic, pid = run([probe, "fetch", "--socket", "unix://" + str(api), "--timeout", "5s"], timeout=10, success=False)
        require(code != 0 and agent_process.poll() is None and api.exists(), "expired-identity-not-denied-by-live-agent")
        log_tail = (state / "agent.log").read_bytes()[offset:]
        explicit_expiry = b"not currently valid" in diagnostic
        api_denial = b"No identity issued" in log_tail and ("pid=" + str(pid)).encode() in log_tail
        require(explicit_expiry or api_denial, "expiry-failure-was-not-identity-specific")
        report["checks"].append("expired-workload-credential-denied-while-agent-remained-alive")
        report["passed"] = True
    except (Stopped, OSError, ValueError, KeyError, subprocess.TimeoutExpired) as error:
        # Never export token/private-state contents or SPIRE logs.
        report["failure"] = str(error) if isinstance(error, Stopped) else type(error).__name__
    finally:
        signal.alarm(0)
        for sig in (signal.SIGINT, signal.SIGTERM, signal.SIGHUP):
            signal.signal(sig, signal.SIG_IGN)
        for child in reversed(children):
            terminate(child)
        for log in logs:
            log.close()
        if state is not None:
            shutil.rmtree(state)
        report["cleanup_complete"] = all(child.poll() is not None for child in children) and (state is None or not state.exists())
        print(json.dumps(report, sort_keys=True))
    return 0 if report["passed"] and report["cleanup_complete"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
