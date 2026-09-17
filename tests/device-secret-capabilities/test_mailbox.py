import json
import os
import subprocess
import sys

binary = sys.argv[1]


def run(arguments=(), environment=None, code=0, queries=0, opens=None):
    result = subprocess.run([binary, *arguments], capture_output=True, text=True,
                            env={**os.environ, **(environment or {})})
    assert result.returncode == code, (result.returncode, result.stdout, result.stderr)
    assert result.stderr.count("QUERY ") == queries, result.stderr
    if opens is not None:
        assert result.stderr.count("OPEN ") == opens, result.stderr
    if not result.stdout.startswith("{"):
        return result.stdout
    state = json.loads(result.stdout)
    assert state["transport"] == "vcio-metadata-only"
    assert state["feasibility"] == "pending"
    return state


assert run(queries=1)["key"] is None
state = run(["--key-id", "1"], queries=3)
assert state["key_count"] == 2 and state["status"] == "observed"
assert state["key"] == dict(id=1, status_bits=0x1301, usage=8,
                            status_return_code=0, usage_return_code=0)
assert run(["--key-id", "32"], {"TEST_ID": "32", "TEST_COUNT": "32"},
           queries=3)["key"]["id"] == 32
for usage in [0, 1, 2, 7, 8, 14]:
    assert run(["--key-id", "1"], {"TEST_USAGE": str(usage)},
               queries=3)["key"]["usage"] == usage
assert run(environment={"TEST_COUNT": "0"}, queries=1)["key_count"] == 0
run(["--key-id", "1"], {"TEST_COUNT": "0"}, code=2, queries=1)
for argument in ["privkey", "genkey", "hmac", "sign", "set-key-status", "set-key-usage",
                 "--device", "--tag", "--raw", "--root-mailbox"]:
    run([argument], code=2, opens=0)
for value in ["0", "33", "-1", "+1", "01", "1x", "18446744073709551616"]:
    run(["--key-id", value], code=2, opens=0)
assert "transport=vcio-metadata-only" in run(["--version"], opens=0)
assert "kaiba-device-secret-metadata" in run(["--help"], opens=0)
for failure in ["TEST_NONROOT", "TEST_OPEN_FAIL", "TEST_STAT_FAIL", "TEST_REGULAR_FILE",
                "TEST_NODE_NONROOT", "TEST_WRONG_MAJOR"]:
    state = run(["--key-id", "1"], {failure: "1"}, code=1,
                opens=0 if failure == "TEST_NONROOT" else 1)
    assert state["status"] == "unavailable" and "key" not in state
for query in [1, 2, 3]:
    state = run(["--key-id", "1"], {"TEST_FAIL_QUERY": str(query)}, code=1,
                queries=1 if query == 1 else 3, opens=1 if query == 1 else 3)
    if query == 1:
        assert state["status"] == "unavailable" and "key" not in state
    else:
        assert state["status"] == "partial"
        assert state["key"]["status_bits" if query == 2 else "usage"] is None
    # Each structural response field, including response length and padding,
    # must be rejected at each query; no unknown value is serialized.
    for word in [0, 1, 2, 3, 4, 6, 7, 8, 9]:
        state = run(["--key-id", "1"], {"TEST_BAD_QUERY": str(query),
                    "TEST_BAD_WORD": str(word)}, code=1,
                    queries=1 if query == 1 else 3)
        if query != 1:
            assert state["key"]["status_bits" if query == 2 else "usage"] is None
    state = run(["--key-id", "1"], {"TEST_BAD_QUERY": str(query), "TEST_BAD_WORD": "5",
                "TEST_BAD_XOR": "0x80000000"}, code=1, queries=1 if query == 1 else 3)
    assert state["status"] == ("unavailable" if query == 1 else "partial")
for usage in [15, 16, 0x7fffffff]:
    assert run(["--key-id", "1"], {"TEST_USAGE": str(usage)}, code=1,
               queries=3)["key"]["usage"] is None
assert run(environment={"TEST_COUNT": "33"}, code=1, queries=1)["status"] == "unavailable"
assert run(environment={"TEST_POSITIVE_RC": "1"}, code=1, queries=1)["status"] == "unavailable"
print("explicit metadata mailbox contract: pass")
