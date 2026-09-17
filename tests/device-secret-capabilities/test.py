import json
import os
import subprocess
import sys

binary = sys.argv[1]


def run(arguments=(), environment=None, code=0):
    result = subprocess.run([binary, *arguments], capture_output=True, text=True,
                            env={**os.environ, **(environment or {})})
    assert result.returncode == code, (result.returncode, result.stderr)
    return result.stdout


assert json.loads(run())["key"] is None
state = json.loads(run(["--key-id", "1"]))
assert state["key_count"] == 2 and state["key"]["status_bits"] == 0x1301
assert state["transport"] == "rpifwcrypto-default"
assert state["feasibility"] == "pending" and state["key"]["usage"] == 8
for operation in ["privkey", "genkey", "hmac", "sign", "set-key-status", "set-key-usage"]:
    assert run([operation], code=2) == ""
for value in ["0", "33", "-1", "+1", "01", "1x", "18446744073709551616"]:
    assert run(["--key-id", value], code=2) == ""
for count in ["-1", "33"]:
    state = json.loads(run(environment={"TEST_KEY_COUNT": count}, code=1))
    assert state["status"] == "unavailable" and "key" not in state
state = json.loads(run(["--key-id", "1"], {"TEST_STATUS_RC": "-4"}, code=1))
assert state["status"] == "partial" and state["key"]["status_bits"] is None
state = json.loads(run(["--key-id", "1"], {"TEST_USAGE_RC": "-8"}, code=1))
assert state["key"]["usage"] is None
assert "fwcrypto=" in run(["--version"])
assert "Queries only" in run(["--help"])
print("read-only capability contract: pass")
