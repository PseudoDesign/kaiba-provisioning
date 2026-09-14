//go:build linux

package campaignstaging

import (
	"context"
	"errors"
	"os"
	"strings"
	"testing"

	"github.com/ams-tech/nixos-kaiba-network/provisioning/internal/provisioning/campaignmedia"
)

func testFixedSDIdentity() campaignmedia.DeviceIdentity {
	return campaignmedia.DeviceIdentity{
		Leg: campaignmedia.LegMalakSD, ConfigID: campaignmedia.MalakSDConfigID,
		Hostname: campaignmedia.MalakSDHostname, Selector: campaignmedia.MalakSDSelector,
		CapacityBytes: campaignmedia.MalakSDCapacityBytes, LogicalSectorSizeBytes: 512,
		DiskGUID: "9c2965e2-34f9-4094-991e-9edb54684311",
	}
}

func TestFixedDeviceOpenerRejectsChangedPolicyBeforeDeviceAccess(t *testing.T) {
	for name, change := range map[string]func(*campaignmedia.DeviceIdentity){
		"selector": func(i *campaignmedia.DeviceIdentity) { i.Selector = "/dev/does-not-exist" },
		"host":     func(i *campaignmedia.DeviceIdentity) { i.Hostname = "other-host" },
		"capacity": func(i *campaignmedia.DeviceIdentity) { i.CapacityBytes -= 512 },
		"sector":   func(i *campaignmedia.DeviceIdentity) { i.LogicalSectorSizeBytes = 4096 },
	} {
		t.Run(name, func(t *testing.T) {
			identity := testFixedSDIdentity()
			change(&identity)
			if _, err := (FixedDeviceOpener{Identity: identity}).Open(context.Background(), true, nil); err == nil || !strings.Contains(err.Error(), "fixed campaign device identity") {
				t.Fatalf("changed fixed identity error = %v", err)
			}
		})
	}
	for _, paths := range [][]string{{"/dev/z", "/dev/a"}, {"/dev/a", "/dev/a"}, {"/dev/disk/by-id/a"}} {
		if _, err := (FixedDeviceOpener{Identity: testFixedSDIdentity(), ProtectedDevicePaths: paths}).Open(context.Background(), true, nil); err == nil || !strings.Contains(err.Error(), "linker-fixed protected") {
			t.Fatalf("invalid protected policy error = %v", err)
		}
	}
}

func TestFixedDeviceOpenerRejectsWrongExecutionHostBeforeInventory(t *testing.T) {
	hostname, err := os.Hostname()
	if err != nil {
		t.Fatal(err)
	}
	if hostname == campaignmedia.MalakSDHostname && os.Geteuid() == 0 {
		t.Skip("positive fixed-host access belongs to the disposable VM check")
	}
	_, err = (FixedDeviceOpener{Identity: testFixedSDIdentity()}).Open(context.Background(), true, nil)
	if err == nil || (!strings.Contains(err.Error(), "effective UID 0") && !strings.Contains(err.Error(), "bound to execution host")) {
		t.Fatalf("wrong execution host error = %v", err)
	}
}

func TestFixedDeviceOpenerRejectsCancellationBeforeDeviceAccess(t *testing.T) {
	if _, err := (FixedDeviceOpener{}).Open(nil, true, nil); err == nil {
		t.Fatal("opener accepted a nil context")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := (FixedDeviceOpener{}).Open(ctx, true, nil); !errors.Is(err, context.Canceled) {
		t.Fatalf("canceled opener error = %v", err)
	}
}
