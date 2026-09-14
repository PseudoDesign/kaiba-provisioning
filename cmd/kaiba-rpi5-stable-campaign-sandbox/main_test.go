//go:build linux

package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"

	"github.com/ams-tech/nixos-kaiba-network/provisioning/internal/provisioning/bundle"
	"github.com/ams-tech/nixos-kaiba-network/provisioning/internal/provisioning/campaignmedia"
	"github.com/ams-tech/nixos-kaiba-network/provisioning/internal/provisioning/campaignsandbox"
)

func writeTestRecord(t *testing.T, path string, data []byte) string {
	t.Helper()
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

// This self-consistent preview is solely an approval-parser fixture. Its
// attachment numbers are fictitious, its files do not exist, and it asserts
// neither hardware observation nor physical write authority.
func syntheticPreview(t *testing.T) campaignsandbox.Preview {
	t.Helper()
	p := campaignsandbox.Preview{
		SchemaVersion: campaignsandbox.PreviewSchema, Scope: campaignsandbox.Scope,
		SandboxID: strings.Repeat("a", 64), Directory: campaignsandbox.Attachment{Device: 1, Inode: 1},
		PlanDigest:                 bundle.Sum([]byte("synthetic command-test plan")),
		RecoveryRequirementsDigest: bundle.Sum([]byte("synthetic command-test requirements")),
	}
	for i, leg := range []campaignmedia.Leg{campaignmedia.LegMalakSD, campaignmedia.LegPiLocalNVMe} {
		inode := uint64(10 + 3*i)
		p.Disks = append(p.Disks, campaignsandbox.Disk{
			Leg: leg, Name: fmt.Sprintf("disk-%d.img", i),
			Attachment: campaignsandbox.Attachment{Device: 1, Inode: inode, Size: 512},
			Backups: []campaignsandbox.Range{{
				Name: fmt.Sprintf("backup-%d-0.img", i), Size: 512, SHA256: bundle.Sum([]byte("synthetic backup")),
				Attachment: campaignsandbox.Attachment{Device: 1, Inode: inode + 1, Size: 512},
			}},
			Writes: []campaignsandbox.Range{{
				Name: fmt.Sprintf("source-%d-0.img", i), Size: 512, SHA256: bundle.Sum([]byte("synthetic source")),
				Attachment: campaignsandbox.Attachment{Device: 1, Inode: inode + 2, Size: 512},
			}},
		})
	}
	encoded, err := json.Marshal(p)
	if err != nil {
		t.Fatal(err)
	}
	p.PreviewDigest = bundle.Sum(append([]byte(campaignsandbox.PreviewSchema+"\x00"), encoded...))
	if err := p.Validate(); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestCommandUsageRejectsAmbiguousOrIncompleteArguments(t *testing.T) {
	for name, args := range map[string][]string{
		"no command":               nil,
		"unknown command":          {"stage"},
		"prepare missing options":  {"prepare", "--directory", "/tmp/sandbox"},
		"approve missing reviewer": {"approve", "--preview", "/tmp/preview.json"},
		"execute missing approval": {"execute", "--directory", "/tmp/sandbox"},
		"unknown option":           {"execute", "--device", "/dev/null"},
		"relative path":            {"approve", "--preview", "relative.json", "--reviewer", "reviewer"},
		"unclean path":             {"approve", "--preview", "/tmp/../preview.json", "--reviewer", "reviewer"},
		"empty path":               {"approve", "--preview", "", "--reviewer", "reviewer"},
		"empty reviewer":           {"approve", "--preview", "/tmp/preview.json", "--reviewer", ""},
		"duplicate path":           {"approve", "--preview", "/tmp/preview.json", "--preview", "/tmp/second.json", "--reviewer", "reviewer"},
		"duplicate reviewer":       {"approve", "--preview", "/tmp/preview.json", "--reviewer", "first", "--reviewer", "second"},
		"positional argument":      {"execute", "--directory", "/tmp/sandbox", "--approval", "/tmp/approval.json", "extra"},
	} {
		t.Run(name, func(t *testing.T) {
			var stdout, stderr bytes.Buffer
			if code := run(context.Background(), args, &stdout, &stderr); code != 2 || stdout.Len() != 0 || stderr.Len() == 0 {
				t.Fatalf("exit=%d stdout=%q stderr=%q", code, stdout.String(), stderr.String())
			}
		})
	}
	for _, args := range [][]string{{"--help"}, {"-h"}, {"prepare", "--help"}, {"approve", "--help"}, {"execute", "--help"}} {
		var stdout, stderr bytes.Buffer
		if code := run(context.Background(), args, &stdout, &stderr); code != 0 || stdout.Len() != 0 || !strings.Contains(stderr.String(), "Usage") {
			t.Fatalf("help %q: exit=%d stdout=%q stderr=%q", args, code, stdout.String(), stderr.String())
		}
	}
}

func TestReadRecordRejectsNonregularInputsBeforeParsing(t *testing.T) {
	directory := t.TempDir()
	regular := writeTestRecord(t, filepath.Join(directory, "regular.json"), []byte("{}\n"))
	empty := writeTestRecord(t, filepath.Join(directory, "empty.json"), nil)
	link := filepath.Join(directory, "link.json")
	if err := os.Symlink(regular, link); err != nil {
		t.Fatal(err)
	}
	fifo := filepath.Join(directory, "fifo.json")
	if err := syscall.Mkfifo(fifo, 0o600); err != nil {
		t.Fatal(err)
	}
	oversized := writeTestRecord(t, filepath.Join(directory, "oversized.json"), nil)
	if err := os.Truncate(oversized, 4*1024*1024+1); err != nil {
		t.Fatal(err)
	}
	for name, path := range map[string]string{
		"directory": directory, "symlink": link, "FIFO": fifo, "device": "/dev/null",
		"empty": empty, "oversized": oversized, "missing": filepath.Join(directory, "missing.json"),
	} {
		t.Run(name, func(t *testing.T) {
			parsed := false
			_, err := readRecord(path, func(encoded []byte) ([]byte, error) { parsed = true; return encoded, nil })
			if err == nil || parsed {
				t.Fatalf("invalid input reached parser: parsed=%v err=%v", parsed, err)
			}
		})
	}
	got, err := readRecord(regular, func(encoded []byte) ([]byte, error) { return encoded, nil })
	if err != nil || !bytes.Equal(got, []byte("{}\n")) {
		t.Fatalf("regular bytes changed: %q, %v", got, err)
	}
	parseError := errors.New("reject malformed record")
	if _, err := readRecord(regular, func([]byte) (string, error) { return "", parseError }); !errors.Is(err, parseError) {
		t.Fatalf("parser error lost: %v", err)
	}
}

func TestApproveEmitsExactlyOneSyntheticCanonicalRecord(t *testing.T) {
	p := syntheticPreview(t)
	encoded, err := p.CanonicalJSON()
	if err != nil {
		t.Fatal(err)
	}
	path := writeTestRecord(t, filepath.Join(t.TempDir(), "preview.json"), encoded)
	var stdout, stderr bytes.Buffer
	if code := run(context.Background(), []string{"approve", "--preview", path, "--reviewer", "cli-test-reviewer"}, &stdout, &stderr); code != 0 {
		t.Fatalf("exit=%d stderr=%q", code, stderr.String())
	}
	approval, err := campaignsandbox.ParseApproval(stdout.Bytes())
	if err != nil {
		t.Fatal(err)
	}
	if approval.PreviewDigest != p.PreviewDigest || approval.Reviewer != "cli-test-reviewer" || approval.PhysicalWritesAuthorized || approval.Scope != campaignsandbox.Scope {
		t.Fatalf("approval changed its input binding or synthetic boundary: %#v", approval)
	}
	if stderr.Len() != 0 || bytes.Count(stdout.Bytes(), []byte{'\n'}) != 1 {
		t.Fatalf("noncanonical output or unexpected diagnostic: stdout=%q stderr=%q", stdout.String(), stderr.String())
	}
	after, err := os.ReadFile(path)
	if err != nil || !bytes.Equal(after, encoded) {
		t.Fatalf("approval mutated its preview input: %v", err)
	}
}

type failingOutput struct{}

func (failingOutput) Write([]byte) (int, error) { return 0, errors.New("output unavailable") }

type shortOutput struct{}

func (shortOutput) Write(encoded []byte) (int, error) { return len(encoded) - 1, nil }

func TestApproveRejectsInvalidPreviewReviewerAndOutputFailure(t *testing.T) {
	p := syntheticPreview(t)
	encoded, err := p.CanonicalJSON()
	if err != nil {
		t.Fatal(err)
	}
	directory := t.TempDir()
	for name, input := range map[string][]byte{
		"malformed":             []byte("not JSON\n"),
		"missing final newline": bytes.TrimSuffix(encoded, []byte{'\n'}),
		"extra final newline":   append(append([]byte(nil), encoded...), '\n'),
		"physical authority":    bytes.Replace(encoded, []byte(`"physical_staging_ready":false`), []byte(`"physical_staging_ready":true`), 1),
		"hardware evidence":     bytes.Replace(encoded, []byte(`"hardware_observed":false`), []byte(`"hardware_observed":true`), 1),
		"stale digest":          bytes.Replace(encoded, []byte(strings.Repeat("a", 64)), []byte(strings.Repeat("b", 64)), 1),
		"unknown field":         bytes.Replace(encoded, []byte(`{"schema_version":`), []byte(`{"authority":true,"schema_version":`), 1),
	} {
		t.Run(name, func(t *testing.T) {
			path := writeTestRecord(t, filepath.Join(directory, name+".json"), input)
			var stdout, stderr bytes.Buffer
			if code := run(context.Background(), []string{"approve", "--preview", path, "--reviewer", "reviewer"}, &stdout, &stderr); code != 1 || stdout.Len() != 0 || stderr.Len() == 0 {
				t.Fatalf("invalid preview accepted: exit=%d stdout=%q stderr=%q", code, stdout.String(), stderr.String())
			}
		})
	}
	validPath := writeTestRecord(t, filepath.Join(directory, "valid.json"), encoded)
	for _, reviewer := range []string{"two words", "newline\n", "nonascii-é", strings.Repeat("x", 129)} {
		var stdout, stderr bytes.Buffer
		if code := run(context.Background(), []string{"approve", "--preview", validPath, "--reviewer", reviewer}, &stdout, &stderr); code != 1 || stdout.Len() != 0 {
			t.Fatalf("invalid reviewer accepted: exit=%d stdout=%q", code, stdout.String())
		}
	}
	for _, output := range []io.Writer{failingOutput{}, shortOutput{}} {
		var stderr bytes.Buffer
		if code := run(context.Background(), []string{"approve", "--preview", validPath, "--reviewer", "reviewer"}, output, &stderr); code != 1 || stderr.Len() == 0 {
			t.Fatalf("output failure reported success: exit=%d stderr=%q", code, stderr.String())
		}
	}
}

func prepareArguments(t *testing.T, directory string) ([]string, map[string]string) {
	t.Helper()
	fixtureRoot, err := filepath.Abs("../../internal/provisioning/campaignmedia/testdata/recovery-v1alpha2")
	if err != nil {
		t.Fatal(err)
	}
	planPath := filepath.Join(fixtureRoot, "staging-plan.json")
	plan, err := readRecord(planPath, campaignmedia.ParseStagingPlan)
	if err != nil {
		t.Fatal(err)
	}
	envelopes := make([]campaignmedia.InitialGPTRecoveryEnvelopeV1Alpha2, 2)
	for index, name := range []string{"sd-envelope.json", "nvme-envelope.json"} {
		envelopes[index], err = readRecord(filepath.Join(fixtureRoot, name), campaignmedia.ParseInitialGPTRecoveryEnvelopeV1Alpha2)
		if err != nil {
			t.Fatal(err)
		}
	}
	requirements, err := campaignmedia.NewRecoveryBackupRequirementsV1Alpha2(plan, envelopes)
	if err != nil {
		t.Fatal(err)
	}
	encoded, err := requirements.CanonicalJSON()
	if err != nil {
		t.Fatal(err)
	}
	inputs := t.TempDir()
	paths := map[string]string{
		"directory": directory, "staging-plan": planPath,
		"requirements":  writeTestRecord(t, filepath.Join(inputs, "requirements.json"), encoded),
		"sd-envelope":   filepath.Join(fixtureRoot, "sd-envelope.json"),
		"nvme-envelope": filepath.Join(fixtureRoot, "nvme-envelope.json"),
	}
	for _, role := range []string{"sd-image", "nvme-image", "boot-filesystem", "root-data", "root-hash", "release-filesystem"} {
		paths[role] = writeTestRecord(t, filepath.Join(inputs, role+".img"), []byte("untouched "+role))
	}
	args := []string{"prepare"}
	for _, name := range []string{"directory", "staging-plan", "requirements", "sd-envelope", "nvme-envelope", "sd-image", "nvme-image", "boot-filesystem", "root-data", "root-hash", "release-filesystem"} {
		args = append(args, "--"+name, paths[name])
	}
	return args, paths
}

func replaceArgument(t *testing.T, args []string, name, value string) {
	t.Helper()
	for index := 1; index+1 < len(args); index += 2 {
		if args[index] == "--"+name {
			args[index+1] = value
			return
		}
	}
	t.Fatalf("missing argument %q", name)
}

func TestMalformedPrepareHasNoSandboxOrSourceSideEffects(t *testing.T) {
	for _, name := range []string{"staging-plan", "requirements", "sd-envelope", "nvme-envelope", "swapped envelopes", "detached requirements"} {
		t.Run(name, func(t *testing.T) {
			root := t.TempDir()
			directory := filepath.Join(root, "sandbox")
			args, paths := prepareArguments(t, directory)
			switch name {
			case "swapped envelopes":
				replaceArgument(t, args, "sd-envelope", paths["nvme-envelope"])
				replaceArgument(t, args, "nvme-envelope", paths["sd-envelope"])
			case "detached requirements":
				requirements, err := readRecord(paths["requirements"], campaignmedia.ParseRecoveryBackupRequirementsV1Alpha2)
				if err != nil {
					t.Fatal(err)
				}
				requirements.StagingPlanDigest = bundle.Sum([]byte("different sealed plan"))
				requirements, err = requirements.Seal()
				if err != nil {
					t.Fatal(err)
				}
				encoded, err := requirements.CanonicalJSON()
				if err != nil {
					t.Fatal(err)
				}
				replaceArgument(t, args, "requirements", writeTestRecord(t, filepath.Join(root, "detached.json"), encoded))
			default:
				replaceArgument(t, args, name, writeTestRecord(t, filepath.Join(root, "malformed.json"), []byte("{}\n")))
			}
			var stdout, stderr bytes.Buffer
			if code := run(context.Background(), args, &stdout, &stderr); code != 1 || stdout.Len() != 0 || stderr.Len() == 0 {
				t.Fatalf("invalid prepare accepted: exit=%d stdout=%q stderr=%q", code, stdout.String(), stderr.String())
			}
			if _, err := os.Lstat(directory); !errors.Is(err, os.ErrNotExist) {
				t.Fatalf("malformed preparation created a sandbox: %v", err)
			}
			for _, role := range []string{"sd-image", "nvme-image", "boot-filesystem", "root-data", "root-hash", "release-filesystem"} {
				encoded, err := os.ReadFile(paths[role])
				if err != nil || string(encoded) != "untouched "+role {
					t.Fatalf("malformed preparation altered %s: %q, %v", role, encoded, err)
				}
			}
		})
	}
}

func TestExecuteRejectsInvalidApprovalWithoutOpeningSandbox(t *testing.T) {
	p := syntheticPreview(t)
	approval, err := campaignsandbox.Approve(p, "command-test")
	if err != nil {
		t.Fatal(err)
	}
	encoded, err := approval.CanonicalJSON()
	if err != nil {
		t.Fatal(err)
	}
	for name, input := range map[string][]byte{
		"malformed":              []byte("{}\n"),
		"noncanonical":           append([]byte(" "), encoded...),
		"physical authorization": bytes.Replace(encoded, []byte(`"physical_writes_authorized":false`), []byte(`"physical_writes_authorized":true`), 1),
		"stale digest":           bytes.Replace(encoded, []byte(`"reviewer":"command-test"`), []byte(`"reviewer":"substituted"`), 1),
	} {
		t.Run(name, func(t *testing.T) {
			directory := t.TempDir()
			sandbox := filepath.Join(directory, "absent-sandbox")
			path := writeTestRecord(t, filepath.Join(directory, "approval.json"), input)
			var stdout, stderr bytes.Buffer
			if code := run(context.Background(), []string{"execute", "--directory", sandbox, "--approval", path}, &stdout, &stderr); code != 1 || stdout.Len() != 0 || stderr.Len() == 0 {
				t.Fatalf("invalid approval accepted: exit=%d stdout=%q stderr=%q", code, stdout.String(), stderr.String())
			}
			if strings.Contains(stderr.String(), sandbox) {
				t.Fatalf("execution tried to open the sandbox before rejecting approval: %s", stderr.String())
			}
			if _, err := os.Lstat(sandbox); !errors.Is(err, os.ErrNotExist) {
				t.Fatalf("created sandbox: %v", err)
			}
		})
	}
}
