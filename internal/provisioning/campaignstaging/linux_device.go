//go:build linux

package campaignstaging

import (
	"context"
	"errors"
	"fmt"
	"os"
	"strings"

	"github.com/ams-tech/nixos-kaiba-network/provisioning/internal/provisioning/campaignmedia"
	"github.com/ams-tech/nixos-kaiba-network/provisioning/internal/provisioning/mediadevice"
	"github.com/ams-tech/nixos-kaiba-network/provisioning/internal/provisioning/mediainventory"
)

// FixedDeviceOpener opens only the execution-host/device pairing in the
// reviewed campaign identity. Callers cannot supply another selector or
// bypass the system inventory. ProtectedDevicePaths are fixed by the station
// executable and must remain observable direct block-device nodes.
type FixedDeviceOpener struct {
	Identity             campaignmedia.DeviceIdentity
	ProtectedDevicePaths []string
}

func (opener FixedDeviceOpener) Open(ctx context.Context, writable bool, expected *mediainventory.TargetFacts) (Target, error) {
	if ctx == nil {
		return nil, errors.New("nil campaign block-device context")
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if err := opener.Identity.Validate(); err != nil {
		return nil, fmt.Errorf("fixed campaign device identity: %w", err)
	}
	policy, err := mediadevice.NewStationPolicy(opener.Identity.Hostname, strings.Join(opener.ProtectedDevicePaths, ","))
	if err != nil {
		return nil, err
	}
	if err := validateExecutionHost(policy); err != nil {
		return nil, err
	}
	inspector := mediadevice.Inspector{}
	geometry := mediadevice.ReadOnlyTargetGeometry{
		SizeBytes: opener.Identity.CapacityBytes, LogicalSectorSizeBytes: opener.Identity.LogicalSectorSizeBytes,
	}
	facts, err := inspector.InspectInactiveSelected(ctx, opener.Identity.Selector, geometry)
	if err != nil {
		return nil, err
	}
	if err := policy.ValidateTarget(facts); err != nil {
		return nil, err
	}
	if expected != nil {
		if err := mediadevice.SameAttachment(*expected, facts); err != nil {
			return nil, err
		}
	}
	file, err := mediadevice.OpenLocked(facts, writable)
	if err != nil {
		return nil, err
	}
	target := &linuxBlockTarget{file: file, facts: facts, policy: policy, geometry: geometry}
	if err := target.Revalidate(ctx); err != nil {
		return nil, errors.Join(err, target.Close())
	}
	return target, nil
}

func validateExecutionHost(policy mediadevice.StationPolicy) error {
	if os.Geteuid() != 0 {
		return errors.New("campaign block-device operations require effective UID 0")
	}
	hostname, err := os.Hostname()
	if err != nil {
		return fmt.Errorf("read execution hostname: %w", err)
	}
	return policy.ValidateHost(hostname)
}

type linuxBlockTarget struct {
	file     *os.File
	facts    mediainventory.TargetFacts
	policy   mediadevice.StationPolicy
	geometry mediadevice.ReadOnlyTargetGeometry
}

func (target *linuxBlockTarget) ReadAt(data []byte, offset int64) (int, error) {
	return target.file.ReadAt(data, offset)
}

func (target *linuxBlockTarget) WriteAt(data []byte, offset int64) (int, error) {
	return target.file.WriteAt(data, offset)
}

func (target *linuxBlockTarget) Sync() error { return target.file.Sync() }

func (target *linuxBlockTarget) Close() error { return mediadevice.CloseLocked(target.file) }

func (target *linuxBlockTarget) Facts() mediainventory.TargetFacts { return target.facts }

// Revalidate repeats host policy, attachment identity, capacity, logical
// sector size, mount/swap usage, and the holders/slaves graph. It also checks
// that the pinned descriptor still agrees with the selected device path.
func (target *linuxBlockTarget) Revalidate(ctx context.Context) error {
	if ctx == nil {
		return errors.New("nil campaign block-device context")
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if err := validateExecutionHost(target.policy); err != nil {
		return err
	}
	if err := mediadevice.ValidateOpened(target.file, target.facts); err != nil {
		return err
	}
	if _, err := (mediadevice.Inspector{}).ReinspectInactiveSame(ctx, target.facts.RequestedPath, target.geometry, target.facts); err != nil {
		return err
	}
	if err := target.policy.ValidateTarget(target.facts); err != nil {
		return err
	}
	return mediadevice.ValidateOpened(target.file, target.facts)
}
