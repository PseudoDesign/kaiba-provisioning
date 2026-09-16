//go:build linux

package main

import (
	"bytes"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/ams-tech/nixos-kaiba-network/provisioning/internal/provisioning/campaignmedia"
)

func completeArguments() []string {
	return []string{
		"--campaign-plan", "/tmp/plan.json", "--artifact-set", "/tmp/artifacts.json",
		"--sd-disk-guid", "sd", "--nvme-disk-guid", "nvme", "--boot-partition-guid", "boot",
		"--root-data-partition-guid", "data", "--root-hash-partition-guid", "hash", "--release-partition-guid", "release",
		"--boot-filesystem", "/tmp/boot.img", "--root-data", "/tmp/data.img", "--root-hash", "/tmp/hash.img", "--release-filesystem", "/tmp/release.img",
	}
}

func TestCLIMapsExactInputsAndPublishesOnlyAfterSuccess(t *testing.T) {
	var stdout, stderr bytes.Buffer
	status := run(completeArguments(), &stdout, &stderr, func(request preparation) ([]byte, error) {
		if request.campaignPath != "/tmp/plan.json" || request.artifactPath != "/tmp/artifacts.json" ||
			request.guids != (campaignmedia.StagingGUIDs{SDDisk: "sd", NVMeDisk: "nvme", Boot: "boot", RootData: "data", RootHash: "hash", Release: "release"}) ||
			len(request.payloadPaths) != 4 || request.payloadPaths[campaignmedia.PartitionRootHash] != "/tmp/hash.img" {
			t.Fatalf("incorrect input mapping: %+v", request)
		}
		if stdout.Len() != 0 {
			t.Fatal("published before validation")
		}
		return []byte(`{"validated":true}`), nil
	})
	if status != 0 || stdout.String() != "{\"validated\":true}\n" || stderr.Len() != 0 {
		t.Fatalf("status/output/error: %d %q %q", status, stdout.String(), stderr.String())
	}
	stdout.Reset()
	stderr.Reset()
	status = run(completeArguments(), &stdout, &stderr, func(preparation) ([]byte, error) {
		return []byte("partial"), errors.New("payload changed")
	})
	if status != 1 || stdout.Len() != 0 || !strings.Contains(stderr.String(), "payload changed") {
		t.Fatal("failed validation published partial output")
	}
}

func TestCLIRejectsMissingDuplicateTrailingAndAuthorityArguments(t *testing.T) {
	cases := [][]string{nil, {"--help"}, append(completeArguments(), "trailing"), append(completeArguments(), "--device", "/dev/null"), append(completeArguments(), "--output", "/tmp/output")}
	for index := 0; index < len(completeArguments()); index += 2 {
		args := completeArguments()
		cases = append(cases, append(append([]string(nil), args[:index]...), args[index+2:]...))
		cases = append(cases, append(completeArguments(), args[index], args[index+1]))
	}
	for _, args := range cases {
		t.Run(strings.Join(args, " "), func(t *testing.T) {
			var stdout, stderr bytes.Buffer
			status := run(args, &stdout, &stderr, func(preparation) ([]byte, error) {
				t.Fatal("invalid flags reached preparation")
				return nil, nil
			})
			want := 2
			if len(args) == 1 && args[0] == "--help" {
				want = 0
			}
			if status != want || stdout.Len() != 0 {
				t.Fatalf("status/output = %d %q", status, stdout.String())
			}
		})
	}
}

func TestPublicFileBoundaryRejectsSpecialPathsAndChanges(t *testing.T) {
	root := t.TempDir()
	regular := filepath.Join(root, "input")
	if err := os.WriteFile(regular, []byte("source"), 0o600); err != nil {
		t.Fatal(err)
	}
	link, fifo := filepath.Join(root, "link"), filepath.Join(root, "fifo")
	if err := os.Symlink(regular, link); err != nil {
		t.Fatal(err)
	}
	if err := syscall.Mkfifo(fifo, 0o600); err != nil {
		t.Fatal(err)
	}
	aliasDirectory := filepath.Join(root, "parent-link")
	if err := os.Symlink(root, aliasDirectory); err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{link, fifo, root, filepath.Join(aliasDirectory, "input"), "/dev/null", "relative", root + "/../input"} {
		t.Run(path, func(t *testing.T) {
			done := make(chan error, 1)
			go func() {
				file, err := openPublicFile(path, 100)
				if file != nil {
					_ = file.file.Close()
				}
				done <- err
			}()
			select {
			case err := <-done:
				if err == nil {
					t.Fatal("accepted unsafe public input")
				}
			case <-time.After(time.Second):
				t.Fatal("blocked opening a special file")
			}
		})
	}
	file, err := openPublicFile(regular, 100)
	if err != nil {
		t.Fatal(err)
	}
	defer file.file.Close()
	data, err := io.ReadAll(file.file)
	if err != nil || string(data) != "source" || file.revalidate() != nil {
		t.Fatal("valid pinned regular input failed")
	}
	if err := os.WriteFile(regular, []byte("change"), 0o600); err != nil {
		t.Fatal(err)
	}
	// Rapid same-size writes can share both filesystem timestamps. Give the
	// metadata revalidation check a deterministic change without sleeping.
	changedAt := time.Unix(file.identity.mtime.Sec, file.identity.mtime.Nsec).Add(time.Second)
	if err := os.Chtimes(regular, changedAt, changedAt); err != nil {
		t.Fatal(err)
	}
	if err := file.revalidate(); err == nil {
		t.Fatal("missed same-inode input change")
	}
	if _, err := openPublicFile(regular, 5); err == nil {
		t.Fatal("accepted oversized public input")
	}
	file2, err := openPublicFile(regular, 100)
	if err != nil {
		t.Fatal(err)
	}
	defer file2.file.Close()
	if err := os.Rename(regular, regular+".old"); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(regular, []byte("change"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := file2.revalidate(); err == nil {
		t.Fatal("missed path replacement by another inode")
	}
}

func fileRequest(t *testing.T, campaignJSON []byte) preparation {
	t.Helper()
	root := t.TempDir()
	request := preparation{campaignPath: filepath.Join(root, "campaign.json"), artifactPath: filepath.Join(root, "artifacts.json"), payloadPaths: make(map[campaignmedia.PartitionRole]string)}
	if err := os.WriteFile(request.campaignPath, campaignJSON, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(request.artifactPath, []byte("{}"), 0o600); err != nil {
		t.Fatal(err)
	}
	for _, role := range []campaignmedia.PartitionRole{campaignmedia.PartitionBootFilesystem, campaignmedia.PartitionRootData, campaignmedia.PartitionRootHash, campaignmedia.PartitionReleaseFilesystem} {
		path := filepath.Join(root, string(role)+".img")
		if err := os.WriteFile(path, make([]byte, 512), 0o600); err != nil {
			t.Fatal(err)
		}
		request.payloadPaths[role] = path
	}
	return request
}

func TestPreparationRejectsHardlinkRoleAliasesBeforeParsing(t *testing.T) {
	request := fileRequest(t, []byte("{}"))
	alias := request.payloadPaths[campaignmedia.PartitionRootHash]
	if err := os.Remove(alias); err != nil {
		t.Fatal(err)
	}
	if err := os.Link(request.payloadPaths[campaignmedia.PartitionRootData], alias); err != nil {
		t.Fatal(err)
	}
	if _, err := prepareFromFiles(request); err == nil || !strings.Contains(err.Error(), "same opened file identity") {
		t.Fatalf("hardlink alias was not rejected before parsing: %v", err)
	}
}

func TestPreparationRejectsDuplicateAndTrailingJSON(t *testing.T) {
	for _, encoded := range [][]byte{[]byte(`{"schema_version":"x","schema_version":"x"}`), []byte(`{} {}`)} {
		request := fileRequest(t, encoded)
		if output, err := prepareFromFiles(request); err == nil || len(output) != 0 || !strings.Contains(err.Error(), "parse campaign plan") {
			t.Fatalf("malformed campaign JSON accepted: %v", err)
		}
	}
}
