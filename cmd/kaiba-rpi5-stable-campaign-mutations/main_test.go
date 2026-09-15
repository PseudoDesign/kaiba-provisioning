package main

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/ams-tech/nixos-kaiba-network/provisioning/internal/provisioning/campaignprepare"
)

func inputPaths(t *testing.T) ([]string, string) {
	t.Helper()
	root := t.TempDir()
	args := []string{}
	for _, name := range []string{"policy", "root-public-key", "positive-manifest", "replacement-manifest", "revoked-manifest"} {
		path := filepath.Join(root, name)
		if err := os.WriteFile(path, []byte(name), 0600); err != nil {
			t.Fatal(err)
		}
		args = append(args, "--"+name, path)
	}
	output := filepath.Join(root, "output")
	return append(args, "--output", output), output
}
func boundaryOutputs() map[string][]byte {
	out := make(map[string][]byte)
	for index := 0; index < 20; index++ {
		out[fmt.Sprintf("fixture-%02d.json", index)] = []byte(fmt.Sprintf(`{"index":%d}`, index))
	}
	return out
}

func TestCLIReadsSnapshotsAndPublishesWholeNewDirectory(t *testing.T) {
	args, output := inputPaths(t)
	t.Cleanup(func() { _ = os.Chmod(output, 0700) })
	var stdout, stderr bytes.Buffer
	calls := 0
	status := runWithBuilder(args, &stdout, &stderr, func(input campaignprepare.MutationInputs) (map[string][]byte, error) {
		calls++
		want := campaignprepare.MutationInputs{PolicyJSON: []byte("policy"), RootPublicPEM: []byte("root-public-key"), PositiveManifestJSON: []byte("positive-manifest"), ReplacementManifestJSON: []byte("replacement-manifest"), RevokedManifestJSON: []byte("revoked-manifest")}
		if !reflect.DeepEqual(input, want) {
			t.Fatal("CLI substituted input roles")
		}
		if _, err := os.Stat(output); !os.IsNotExist(err) {
			t.Fatal("published output before verification")
		}
		return boundaryOutputs(), nil
	})
	if status != exitOK || calls != 1 {
		t.Fatalf("status=%d calls=%d stderr=%s", status, calls, &stderr)
	}
	entries, err := os.ReadDir(output)
	if err != nil || len(entries) != 20 {
		t.Fatalf("entries=%d err=%v", len(entries), err)
	}
	for name, want := range boundaryOutputs() {
		got, err := os.ReadFile(filepath.Join(output, name))
		if err != nil || !bytes.Equal(got, want) {
			t.Fatalf("wrong output%s: %v", name, err)
		}
		info, err := os.Stat(filepath.Join(output, name))
		if err != nil || info.Mode().Perm() != 0444 {
			t.Fatal("output file not immutable")
		}
	}
	if !strings.Contains(stdout.String(), `"file_count":20`) || stderr.Len() != 0 {
		t.Fatalf("stdout=%s stderr=%s", &stdout, &stderr)
	}
	stdout.Reset()
	stderr.Reset()
	if status := runWithBuilder(args, &stdout, &stderr, func(campaignprepare.MutationInputs) (map[string][]byte, error) {
		t.Fatal("builder ran for existing output")
		return nil, nil
	}); status != exitInvalid {
		t.Fatal("accepted existing output")
	}
}

func TestCLIRejectsBeforePublishing(t *testing.T) {
	for _, name := range []string{"duplicate flag", "positional", "runtime signer", "relative path", "missing flag", "same inode", "hardlink", "FIFO", "symlink", "parent symlink", "oversize", "empty"} {
		t.Run(name, func(t *testing.T) {
			args, output := inputPaths(t)
			switch name {
			case "duplicate flag":
				args = append(args, "--policy", args[1])
			case "positional":
				args = append(args, "unexpected")
			case "runtime signer":
				args = append(args, "--private-key", "anything")
			case "relative path":
				args[1] = "relative"
			case "missing flag":
				args = args[2:]
			case "same inode":
				args[3] = args[1]
			case "hardlink":
				os.Remove(args[3])
				if err := os.Link(args[1], args[3]); err != nil {
					t.Fatal(err)
				}
			case "FIFO":
				os.Remove(args[1])
				if err := syscall.Mkfifo(args[1], 0600); err != nil {
					t.Fatal(err)
				}
			case "symlink":
				os.Remove(args[1])
				if err := os.Symlink(args[3], args[1]); err != nil {
					t.Fatal(err)
				}
			case "parent symlink":
				link := filepath.Join(t.TempDir(), "link")
				if err := os.Symlink(filepath.Dir(args[1]), link); err != nil {
					t.Fatal(err)
				}
				args[1] = filepath.Join(link, filepath.Base(args[1]))
			case "oversize":
				if err := os.WriteFile(args[1], bytes.Repeat([]byte("x"), campaignprepare.MutationMetadataMaxBytes+1), 0600); err != nil {
					t.Fatal(err)
				}
			case "empty":
				if err := os.WriteFile(args[1], nil, 0600); err != nil {
					t.Fatal(err)
				}
			}
			var stdout, stderr bytes.Buffer
			done := make(chan int, 1)
			go func() {
				done <- runWithBuilder(args, &stdout, &stderr, func(campaignprepare.MutationInputs) (map[string][]byte, error) {
					return nil, errors.New("should not reach builder")
				})
			}()
			select {
			case status := <-done:
				if status == exitOK || stdout.Len() != 0 {
					t.Fatalf("status=%d stdout=%s", status, &stdout)
				}
			case <-time.After(time.Second):
				t.Fatal("CLI blocked on invalid input")
			}
			if _, err := os.Lstat(output); !os.IsNotExist(err) {
				t.Fatalf("published rejected output: %v", err)
			}
		})
	}
}

func TestProductionCLIRejectsUnverifiedInputs(t *testing.T) {
	args, output := inputPaths(t)
	var stdout, stderr bytes.Buffer
	if status := run(args, &stdout, &stderr); status != exitInvalid {
		t.Fatalf("status=%d stderr=%s", status, &stderr)
	}
	if _, err := os.Stat(output); !os.IsNotExist(err) {
		t.Fatal("production builder published invalid inputs")
	}
}

func TestPublicationDoesNotReplaceRacingDestination(t *testing.T) {
	root := t.TempDir()
	output := filepath.Join(root, "output")
	if err := os.Mkdir(output, 0700); err != nil {
		t.Fatal(err)
	}
	if err := publishDirectory(output, boundaryOutputs()); !errors.Is(err, syscall.EEXIST) {
		t.Fatalf("expected atomic no-replace refusal, got %v", err)
	}
	entries, err := os.ReadDir(output)
	if err != nil || len(entries) != 0 {
		t.Fatalf("changed existing output: %v %v", entries, err)
	}
	parents, err := os.ReadDir(root)
	if err != nil || len(parents) != 1 {
		t.Fatalf("left temporary partial publication: %v %v", parents, err)
	}
}

func TestBuilderFailureHasNoOutputOrTemporaryFiles(t *testing.T) {
	args, output := inputPaths(t)
	var stdout, stderr bytes.Buffer
	status := runWithBuilder(args, &stdout, &stderr, func(campaignprepare.MutationInputs) (map[string][]byte, error) {
		return nil, errors.New("cryptographic verification failed")
	})
	if status != exitInvalid || stdout.Len() != 0 {
		t.Fatal("builder failure not propagated")
	}
	entries, err := os.ReadDir(filepath.Dir(output))
	if err != nil || len(entries) != 5 {
		t.Fatal("failed verification created output entries")
	}
}
