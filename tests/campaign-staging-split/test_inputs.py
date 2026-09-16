import copy
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[2]
spec = importlib.util.spec_from_file_location("staging_inputs", ROOT / "nix/campaign-staging-inputs.py")
tool = importlib.util.module_from_spec(spec)
spec.loader.exec_module(tool)


class InputsTests(unittest.TestCase):
    def setUp(self):
        self.capacity = mock.patch.object(tool, "CAPACITY", 8 * 1024 * 1024)
        self.capacity.start()
        self.addCleanup(self.capacity.stop)
        self.plan = json.loads((ROOT / "internal/provisioning/campaignmedia/testdata/recovery-v1alpha2/staging-plan.json").read_bytes())
        part = self.plan["devices"][1]["partitions"][0]
        self.payload = b"reviewed-public-payload"
        part.update(source_size_bytes=len(self.payload), source_sha256=tool.digest(self.payload), capacity_bytes=tool.CAPACITY, zero_tail_bytes=tool.CAPACITY-len(self.payload), expected_whole_partition_sha256=tool.digest(self.payload + bytes(tool.CAPACITY-len(self.payload))))
        self.plan_bytes = json.dumps(self.plan, separators=(",", ":")).encode() + b"\n"
        self.config_path = "/nix/store/00000000000000000000000000000000-test-configuration.json"
        self.plan_path = "/nix/store/11111111111111111111111111111111-test-plan.json"
        self.payload_path = "/nix/store/22222222222222222222222222222222-test-payload"
        config = {"leg":"pi-local-nvme", "payload_paths":{"release-filesystem":self.payload_path}, "schema_version":tool.CONFIG_SCHEMA,"staging_plan_path":self.plan_path}
        self.config_bytes = json.dumps(config, sort_keys=True, separators=(",", ":")).encode()
        def embedded(path, data):
            return {"path":path,"sha256":tool.digest(data),"size_bytes":len(data),"json":data.decode()}
        self.desc = {"schema_version":tool.DESCRIPTOR_SCHEMA,"target_system":"aarch64-linux","leg":"pi-local-nvme","configuration":embedded(self.config_path,self.config_bytes),"staging_plan":dict(embedded(self.plan_path,self.plan_bytes),plan_digest=self.plan["plan_digest"]),"payloads":[{"role":"release-filesystem","path":self.payload_path,"sha256":part["source_sha256"],"size_bytes":len(self.payload),"partition_size_bytes":tool.CAPACITY,"whole_partition_sha256":part["expected_whole_partition_sha256"]}],"hardware_qualified":False,"production_ready":False}

    def test_validation_opens_no_embedded_paths(self):
        with mock.patch.object(tool, "open_regular", side_effect=AssertionError("unexpected filesystem access")):
            self.assertEqual(tool.validate(tool.encode(self.desc)),self.desc)

    def test_closed_descriptor_and_configuration(self):
        for field in self.desc:
            changed = copy.deepcopy(self.desc)
            del changed[field]
            with self.subTest(missing=field), self.assertRaises((ValueError, KeyError)):
                tool.validate(tool.encode(changed))
        for key, value in (("unknown",False),("leg","malak-sd"),("target_system","x86_64-linux"),("hardware_qualified",True),("production_ready",True)):
            changed = dict(self.desc, **{key:value})
            with self.subTest(field=key), self.assertRaises(ValueError):
                tool.validate(tool.encode(changed))
        for text in ('{"a":1,"a":2}', '{"a":NaN}'):
            with self.assertRaises(ValueError): tool.parse(text.encode())
        changed = copy.deepcopy(self.desc)
        config = json.loads(changed["configuration"]["json"])
        config["device"] = "/dev/null"
        data = tool.encode(config)
        changed["configuration"].update(json=data.decode(),sha256=tool.digest(data),size_bytes=len(data))
        with self.assertRaises(ValueError): tool.validate(tool.encode(changed))

    def test_embedded_and_payload_substitutions(self):
        for group, field, value in (("configuration","sha256","sha256:"+"f"*64),("staging_plan","size_bytes",1),("staging_plan","plan_digest","sha256:"+"f"*64)):
            changed = copy.deepcopy(self.desc)
            changed[group][field] = value
            with self.subTest(group=group,field=field),self.assertRaises(ValueError):tool.validate(tool.encode(changed))
        for field, value in (("path",self.config_path),("sha256","sha256:"+"0"*64),("size_bytes",1),("whole_partition_sha256","sha256:"+"0"*64)):
            changed = copy.deepcopy(self.desc)
            changed["payloads"][0][field] = value
            with self.subTest(field=field),self.assertRaises(ValueError):tool.validate(tool.encode(changed))

    def test_canonical_lf_and_no_private_metadata(self):
        data = tool.encode(self.desc)
        for invalid in (data[:-1],data+b"\n",json.dumps(self.desc,indent=2).encode()):
            with self.assertRaises(ValueError):tool.validate(invalid)
        with self.assertRaises(ValueError):tool.parse(b'{"untrusted":"-----BEGIN PRIVATE KEY-----"}')

    def test_full_source_and_zero_tail_are_verified(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory)/"payload"
            path.write_bytes(self.payload)
            payload = dict(self.desc["payloads"][0],path=str(path))
            tool.verify_payload(payload)
            with self.assertRaisesRegex(ValueError,"padded partition"):
                tool.verify_payload(dict(payload,whole_partition_sha256="sha256:"+"f"*64))
            path.write_bytes(b"x"*len(self.payload))
            with self.assertRaisesRegex(ValueError,"source payload"):
                tool.verify_payload(payload)

    def test_missing_and_changed_actual_inputs(self):
        with mock.patch.object(tool,"read_regular",side_effect=FileNotFoundError):
            with self.assertRaises(FileNotFoundError):tool.verify_inputs(self.desc,self.config_path,self.plan_path)
        with mock.patch.object(tool,"read_regular",return_value=b"substitution"):
            with self.assertRaisesRegex(ValueError,"configuration bytes"):
                tool.verify_inputs(self.desc,self.config_path,self.plan_path)
        with self.assertRaisesRegex(ValueError,"paths differ"):
            tool.verify_inputs(self.desc,"/tmp/alternate",self.plan_path)

    def test_fifo_symlink_and_parent_symlink_refused(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root/"file").write_text("public")
            os.mkfifo(root/"fifo")
            (root/"link").symlink_to(root/"file")
            (root/"parent").symlink_to(root,target_is_directory=True)
            for path in (root/"fifo",root/"link",root/"parent/file"):
                with self.subTest(path=path),self.assertRaises((ValueError,OSError)):
                    tool.read_regular(path)

    def test_component_exact_binding_architecture_and_file_set(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root/"bin").mkdir()
            (root/"share/kaiba").mkdir(parents=True)
            binary = root/tool.BINARY
            # Public synthetic ELF header only; this is never executed.
            blob = b"\x7fELF\x02\x01\x01"+bytes(11)+b"\xb7\x00"+self.config_path.encode()
            binary.write_bytes(blob)
            data = tool.encode(self.desc)
            revision = "a"*40
            manifest = tool.component(data,binary,revision)
            self.assertFalse(manifest["complete_runtime_closure"])
            (root/"share/kaiba/descriptor.json").write_bytes(data)
            (root/"share/kaiba/component.json").write_bytes(tool.encode(manifest))
            tool.verify_component(data,root,revision)
            with self.assertRaises(ValueError):tool.verify_component(data,root,"b"*40)
            (root/"unexpected").write_text("extra")
            with self.assertRaisesRegex(ValueError,"file set"):
                tool.verify_component(data,root,revision)
            (root/"unexpected").unlink()
            binary.write_bytes(blob[:18]+b"\x3e\x00"+blob[20:])
            with self.assertRaisesRegex(ValueError,"AArch64"):
                tool.verify_component(data,root,revision)
            binary.unlink()
            binary.symlink_to(root/"share/kaiba/descriptor.json")
            with self.assertRaises(ValueError):tool.verify_component(data,root,revision)

    @unittest.skipUnless(os.environ.get("KAIBA_STAGING_PLAN_VALIDATOR"), "requires production Go plan checker")
    def test_production_contract_rejects_altered_plan_with_recomputed_raw_hash(self):
        data = (ROOT / "internal/provisioning/campaignmedia/testdata/recovery-v1alpha2/staging-plan.json").read_bytes()
        plan = json.loads(data)
        desc = {"staging_plan": {"json": data.decode(), "plan_digest": plan["plan_digest"]}}
        validator = os.environ["KAIBA_STAGING_PLAN_VALIDATOR"]
        tool.validate_plan_contract(desc, validator)
        # This SD field is outside the preliminary selected-NVMe byte checks.
        # Retaining plan_digest while recomputing the outer raw hash must fail.
        plan["devices"][0]["identity"]["disk_guid"] = "6625eee2-0c8a-402f-8c2f-5a1347652bb2"
        changed = json.dumps(plan, separators=(",", ":")).encode() + b"\n"
        desc["staging_plan"].update(json=changed.decode(), sha256=tool.digest(changed), size_bytes=len(changed))
        with self.assertRaisesRegex(ValueError, "production Go"):
            tool.validate_plan_contract(desc, validator)


if __name__ == "__main__":
    unittest.main()
