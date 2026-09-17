package signedrelease

import (
	"fmt"
	"testing"
)

func TestEEPROMReleaseSchemaCompatibility(t *testing.T) {
	for _, version := range []string{"v1alpha1", "v1alpha2", "v1alpha3", ""} {
		t.Run(version, func(t *testing.T) {
			manifest := []byte(fmt.Sprintf(`{"schema_version":"kaiba.provisioning.rpi5-eeprom-release/%s","device_class":"raspberry-pi-5-model-b-v1alpha1","source":{},"firmware":{},"provenance":[],"toolchain":{},"required_capability":{},"authority":{}}`, version))
			err := validateEEPROMRelease(manifest)
			supported := version == "v1alpha1" || version == "v1alpha2"
			if (err == nil) != supported {
				t.Fatalf("supported=%v, error=%v", supported, err)
			}
		})
	}
}
