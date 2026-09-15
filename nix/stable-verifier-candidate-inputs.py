"""Validate and copy a closed public verifier configuration inside a Nix build."""

import json
import os
from pathlib import Path
import re
import stat
from urllib.parse import urlsplit


LIMITS = {
    "authority-ca.pem": 65536,
    "candidate.json": 16384,
    "policy.json": 1048576,
    "root-public.pem": 16384,
}
KEYS = {
    "schema_version", "verifier_version", "cohort_id", "slot_id",
    "minimum_security_epoch", "authority_url", "authority_key_id", "audience",
    "logical_identity",
}


def unique_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate JSON key")
        result[key] = value
    return result


def validate_config(config):
    if not isinstance(config, dict) or set(config) != KEYS:
        raise ValueError("candidate configuration must have exactly the required fields")
    if config["schema_version"] != "kaiba.provisioning.rpi5-stable-verifier-candidate/v1alpha1":
        raise ValueError("unsupported candidate schema")
    for key in ("verifier_version", "minimum_security_epoch"):
        if type(config[key]) is not int or not 1 <= config[key] <= 2147483647:
            raise ValueError("invalid candidate integer")
    for key in ("cohort_id", "slot_id", "authority_key_id", "audience", "logical_identity"):
        if not isinstance(config[key], str) or not re.fullmatch(r"[a-z0-9][a-z0-9._:-]{0,127}", config[key]):
            raise ValueError("invalid candidate identifier")
    url = config["authority_url"]
    if not isinstance(url, str) or len(url) > 2048 or any(ord(char) <= 32 or ord(char) >= 127 for char in url):
        raise ValueError("invalid authority URL")
    parsed = urlsplit(url)
    if (parsed.scheme != "https" or not parsed.hostname or parsed.username is not None
            or parsed.password is not None or parsed.fragment or parsed.port == 0
            or parsed.path not in ("", "/") or parsed.query):
        raise ValueError("authority URL must be an HTTPS origin without user information, query or fragment")
    # Accessing port also rejects malformed/non-numeric/out-of-range ports.
    _ = parsed.port


def validate_inputs(source, expected_config):
    if sorted(path.name for path in source.iterdir()) != sorted(LIMITS):
        raise ValueError("unexpected public input file set")
    files = {}
    for name, limit in LIMITS.items():
        path = source / name
        info = path.lstat()
        if not stat.S_ISREG(info.st_mode) or not 0 < info.st_size <= limit:
            raise ValueError("invalid public input file")
        files[name] = path.read_bytes()
        if re.search(rb"-----BEGIN [A-Z0-9 -]*PRIVATE KEY-----", files[name]):
            raise ValueError("private key marker in public input")
    def invalid_constant(value):
        raise ValueError("invalid JSON constant: " + value)

    config = json.loads(files["candidate.json"], object_pairs_hook=unique_object, parse_constant=invalid_constant)
    validate_config(config)
    if config != expected_config:
        raise ValueError("candidate configuration differs from evaluated Nix configuration")
    policy = json.loads(files["policy.json"], object_pairs_hook=unique_object, parse_constant=invalid_constant)
    if not isinstance(policy, dict) or policy.get("schema_version") != "kaiba.provisioning.rpi5-stable-verifier-policy/v1alpha1":
        raise ValueError("unsupported policy schema")
    # OpenSSL's command-line parsers accept trailing material; close the PEM set
    # here before those tools validate the actual public object.
    for name, label in (("root-public.pem", "PUBLIC KEY"), ("authority-ca.pem", "CERTIFICATE")):
        pattern = rb"-----BEGIN " + label.encode() + rb"-----\n[A-Za-z0-9+/=\r\n]+-----END " + label.encode() + rb"-----\n?"
        if not re.fullmatch(pattern, files[name]):
            raise ValueError("public PEM must contain exactly one expected object")
    return files


if __name__ == "__main__":
    files = validate_inputs(Path(os.environ["inputsPath"]), json.loads(os.environ["expectedConfig"]))
    output = Path(os.environ["out"])
    output.mkdir()
    for name, data in files.items():
        (output / name).write_bytes(data)
