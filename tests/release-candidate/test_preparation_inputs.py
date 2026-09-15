import importlib.util
import json
from pathlib import Path
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[2]


def load(name):
    spec = importlib.util.spec_from_file_location(name, ROOT / "nix" / (name + ".py"))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


candidate = load("stable-verifier-candidate-inputs")
assembly = load("campaign-preparation-inputs")


class PreparationInputsTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)

    def config(self):
        return {
            "schema_version": "kaiba.provisioning.rpi5-stable-verifier-candidate/v1alpha1",
            "verifier_version": 1, "minimum_security_epoch": 1,
            "cohort_id": "development", "slot_id": "a", "authority_key_id": "authority:test",
            "audience": "verifier:test", "logical_identity": "pi:test",
            "authority_url": "https://192.0.2.1:8443",
        }

    def candidate_inputs(self):
        source = self.root / "candidate"
        source.mkdir()
        config = self.config()
        (source / "candidate.json").write_text(json.dumps(config))
        (source / "policy.json").write_text(json.dumps({"schema_version": "kaiba.provisioning.rpi5-stable-verifier-policy/v1alpha1"}))
        # These tests cover the closed transport; OpenSSL validates the public
        # objects separately in the Nix constructor.
        (source / "root-public.pem").write_text("-----BEGIN PUBLIC KEY-----\nAA==\n-----END PUBLIC KEY-----\n")
        (source / "authority-ca.pem").write_text("-----BEGIN CERTIFICATE-----\nAA==\n-----END CERTIFICATE-----\n")
        return source, config

    def test_candidate_rejects_duplicate_and_substituted_configuration(self):
        source, config = self.candidate_inputs()
        self.assertEqual(set(candidate.validate_inputs(source, config)), set(candidate.LIMITS))
        (source / "candidate.json").write_text('{"verifier_version": 9,' + json.dumps(config)[1:])
        with self.assertRaisesRegex(ValueError, "duplicate"):
            candidate.validate_inputs(source, config)
        (source / "candidate.json").write_text(json.dumps(config))
        with self.assertRaisesRegex(ValueError, "differs"):
            candidate.validate_inputs(source, {**config, "cohort_id": "other"})

    def test_candidate_rejects_extra_private_symlink_and_multiple_pem_objects(self):
        source, config = self.candidate_inputs()
        extra = source / "extra"
        extra.write_text("private")
        with self.assertRaisesRegex(ValueError, "file set"):
            candidate.validate_inputs(source, config)
        extra.unlink()
        pem = source / "root-public.pem"
        original = pem.read_bytes()
        pem.write_bytes(original + original)
        with self.assertRaisesRegex(ValueError, "exactly one"):
            candidate.validate_inputs(source, config)
        pem.write_bytes(b"-----BEGIN RSA PRIVATE KEY-----\n")
        with self.assertRaisesRegex(ValueError, "private key"):
            candidate.validate_inputs(source, config)
        pem.unlink()
        pem.symlink_to(source / "authority-ca.pem")
        with self.assertRaisesRegex(ValueError, "file"):
            candidate.validate_inputs(source, config)

    def test_candidate_rejects_runtime_selectors_and_bad_urls(self):
        for url in ("http://192.0.2.1", "https://user@192.0.2.1", "https://192.0.2.1/#x", "https://192.0.2.1:abc", "https://192.0.2.1\n", "https://192.0.2.1/api", "https://192.0.2.1?x=1"):
            with self.subTest(url=url), self.assertRaises(ValueError):
                candidate.validate_config({**self.config(), "authority_url": url})
        for change in ({"extra_modules": []}, {"verifier_version": True}, {"cohort_id": "../other"}):
            with self.subTest(change=change), self.assertRaises(ValueError):
                candidate.validate_config({**self.config(), **change})

    def release_inputs(self):
        directories = [self.root / name for name in ("release", "trust", "boot", "mutations", "roots")]
        for directory in directories:
            directory.mkdir()
        release, trust, boot, mutations, roots = directories
        names = ["cmdline.txt", "device-tree.dtb", "dm-verity.json", "initramfs", "kernel", "overlays/actual.dtbo", "release-manifest.json", "root.img", "slot.txt"]
        for name in names:
            path = release / name
            path.parent.mkdir(exist_ok=True)
            path.write_text("fixture " + name)
        (release / "release-manifest.json").write_text(json.dumps({"overlays": [{"name": "actual"}]}))
        for name in ("authority-ca.pem", "root-public.pem", "policy.json"):
            (trust / name).write_text("public " + name)
        for name in ("boot.img", "public.pem"):
            (boot / name).write_text("public " + name)
        for index in range(20):
            (mutations / f"mutation-{index}.json").write_text(str(index))
        (roots / "root-data.img").write_bytes((release / "root.img").read_bytes())
        (roots / "root-hash.img").write_text("root hash fixture")
        allowlist = self.root / "allowlist"
        allowlist.write_text("\n".join(names) + "\n")
        return (release, allowlist, trust, boot, mutations, roots)

    def test_plan_inputs_bind_exact_inventory_and_distinct_role_files(self):
        inputs = self.release_inputs()
        output = self.root / "output"
        assembly.materialize(output, *inputs)
        self.assertEqual(len((output / "public-input-names.txt").read_text().splitlines()), 27)
        self.assertEqual(len((output / "mutation-target-names.txt").read_text().splitlines()), 10)
        domain, inventory = (output / "public-inputs/positive-release-tree").read_bytes().split(b"\0", 1)
        self.assertEqual(domain, b"kaiba.provisioning.rpi5-stable-verifier-campaign-release-tree.v1alpha1")
        records = json.loads(inventory)
        self.assertEqual([record["path"] for record in records], inputs[1].read_text().splitlines())
        release_root = output / "mutation-targets/release/root.img"
        media_root = output / "mutation-targets/media/root-data"
        self.assertEqual(release_root.read_bytes(), media_root.read_bytes())
        self.assertNotEqual(release_root.stat().st_ino, media_root.stat().st_ino)
        self.assertTrue((output / "mutation-targets/release/overlays/actual.dtbo").is_file())

    def test_plan_inputs_reject_unlisted_release_bytes_and_missing_overlay(self):
        inputs = self.release_inputs()
        (inputs[0] / "unlisted").write_text("unreviewed")
        with self.assertRaisesRegex(ValueError, "allowlist"):
            assembly.materialize(self.root / "bad-extra", *inputs)
        (inputs[0] / "unlisted").unlink()
        (inputs[0] / "release-manifest.json").write_text('{"overlays":[]}')
        with self.assertRaisesRegex(ValueError, "overlay"):
            assembly.materialize(self.root / "bad-overlay", *inputs)


if __name__ == "__main__":
    unittest.main()
