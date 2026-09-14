package stableverifiersigning

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/ams-tech/nixos-kaiba-network/provisioning/internal/provisioning/bundle"
)

func manifestForTest(t *testing.T, intent Intent) map[string]any {
	t.Helper()
	return map[string]any{
		"schema_version": UnsignedManifestSchemaV1Alpha1, "source_revision": intent.SourceRevision,
		"pi_platform_source": map[string]any{"revision": strings.Repeat("a", 40), "nar_hash": "sha256-AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="},
		"boot_image":         map[string]any{"path": "boot.img", "sha256": string(intent.SigningInput.Digest), "size_bytes": intent.SigningInput.SizeBytes},
		"files":              []string{"config.txt", "kaiba/authority-ca.pem", "kaiba/provenance.json", "kaiba/root-public.pem", "kaiba/stable-verifier", "kaiba/stable-verifier-policy.json"},
		"hardware_observed":  false, "production_ready": false, "signing_status": "unsigned_requires_external_root_signature",
	}
}

func TestUnsignedManifestBindsExactProducerBytes(t *testing.T) {
	intent := testIntent(t)
	encoded, err := json.MarshalIndent(manifestForTest(t, intent), "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	encoded = append(encoded, '\n')
	intent.UnsignedManifestDigest = bundle.Sum(encoded)
	if err := ValidateUnsignedManifest(encoded, intent); err != nil {
		t.Fatal(err)
	}
	if err := ValidateUnsignedManifest(encoded[:len(encoded)-1], intent); err == nil || !strings.Contains(err.Error(), "digest") {
		t.Fatalf("removed transport byte was not bound: %v", err)
	}
}

func TestUnsignedManifestRejectsProfileAndArtifactSubstitution(t *testing.T) {
	for name, alter := range map[string]func(map[string]any){
		"provisioner schema": func(value map[string]any) {
			value["schema_version"] = "provisioning.kaiba.network/rpi5-stable-campaign-provisioner-artifact-set/v1alpha1"
		},
		"source":      func(value map[string]any) { value["source_revision"] = strings.Repeat("b", 40) },
		"Pi revision": func(value map[string]any) { value["pi_platform_source"].(map[string]any)["revision"] = "main" },
		"Pi hash": func(value map[string]any) {
			value["pi_platform_source"].(map[string]any)["nar_hash"] = "sha256-AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAB="
		},
		"boot path":             func(value map[string]any) { value["boot_image"].(map[string]any)["path"] = "unsigned/boot.img" },
		"boot digest":           func(value map[string]any) { value["boot_image"].(map[string]any)["sha256"] = string(testDigest("a")) },
		"boot size":             func(value map[string]any) { value["boot_image"].(map[string]any)["size_bytes"] = 32 * 1024 * 1024 },
		"missing false":         func(value map[string]any) { delete(value, "hardware_observed") },
		"hardware claim":        func(value map[string]any) { value["hardware_observed"] = true },
		"production claim":      func(value map[string]any) { value["production_ready"] = true },
		"signed claim":          func(value map[string]any) { value["signing_status"] = "signed" },
		"invented bundle":       func(value map[string]any) { value["bundle_digest"] = string(testDigest("a")) },
		"nested unknown":        func(value map[string]any) { value["boot_image"].(map[string]any)["role"] = "rpi5.eeprom_bootcode" },
		"null":                  func(value map[string]any) { value["production_ready"] = nil },
		"repeated path":         func(value map[string]any) { value["files"].([]string)[0] = "kaiba/authority-ca.pem" },
		"missing verifier path": func(value map[string]any) { value["files"].([]string)[1] = "firmware.bin" },
		"traversal":             func(value map[string]any) { value["files"].([]string)[0] = "../config.txt" },
		"absolute path":         func(value map[string]any) { value["files"].([]string)[0] = "/config.txt" },
		"reserved path":         func(value map[string]any) { value["files"].([]string)[1] = "kaiba/authority-ca.key" },
	} {
		t.Run(name, func(t *testing.T) {
			intent := testIntent(t)
			manifest := manifestForTest(t, intent)
			alter(manifest)
			encoded, err := json.Marshal(manifest)
			if err != nil {
				t.Fatal(err)
			}
			// Even a correctly rebound file digest cannot change the profile or
			// the other approved intent identities.
			intent.UnsignedManifestDigest = bundle.Sum(encoded)
			if err := ValidateUnsignedManifest(encoded, intent); err == nil {
				t.Fatal("accepted invalid/rebound unsigned verifier manifest")
			}
		})
	}
}

func TestUnsignedManifestRejectsCaseFoldedFieldsWithReboundDigest(t *testing.T) {
	for _, object := range []string{"root", "pi_platform_source", "boot_image"} {
		intent := testIntent(t)
		baseline := manifestForTest(t, intent)
		fields := baseline
		if object != "root" {
			fields = baseline[object].(map[string]any)
		}
		for name := range fields {
			for _, retainOriginal := range []bool{false, true} {
				mode := "replacement"
				if retainOriginal {
					mode = "overlay"
				}
				t.Run(object+"/"+name+"/"+mode, func(t *testing.T) {
					manifest := manifestForTest(t, intent)
					target := manifest
					if object != "root" {
						target = manifest[object].(map[string]any)
					}
					target[strings.ToUpper(name)] = target[name]
					if !retainOriginal {
						delete(target, name)
					}
					encoded, err := json.Marshal(manifest)
					if err != nil {
						t.Fatal(err)
					}
					intent.UnsignedManifestDigest = bundle.Sum(encoded)
					if err := ValidateUnsignedManifest(encoded, intent); err == nil {
						t.Fatal("accepted a case-folded field after digest rebinding")
					}
				})
			}
			t.Run(object+"/"+name+"/missing", func(t *testing.T) {
				manifest := manifestForTest(t, intent)
				target := manifest
				if object != "root" {
					target = manifest[object].(map[string]any)
				}
				delete(target, name)
				encoded, err := json.Marshal(manifest)
				if err != nil {
					t.Fatal(err)
				}
				intent.UnsignedManifestDigest = bundle.Sum(encoded)
				if err := ValidateUnsignedManifest(encoded, intent); err == nil {
					t.Fatal("accepted a missing required field after digest rebinding")
				}
			})
		}
	}
}

func TestUnsignedManifestRejectsAliasThatHidesHardwareClaim(t *testing.T) {
	intent := testIntent(t)
	manifest := manifestForTest(t, intent)
	manifest["hardware_observed"] = true
	encoded, err := json.Marshal(manifest)
	if err != nil {
		t.Fatal(err)
	}
	// Put the false alias last, reproducing the encoding/json overlay while
	// preserving the contradictory true value seen by case-sensitive readers.
	encoded = append(encoded[:len(encoded)-1], []byte(`,"HARDWARE_OBSERVED":false}`)...)
	intent.UnsignedManifestDigest = bundle.Sum(encoded)
	if err := ValidateUnsignedManifest(encoded, intent); err == nil {
		t.Fatal("accepted uppercase alias concealing hardware_observed=true")
	}
}
