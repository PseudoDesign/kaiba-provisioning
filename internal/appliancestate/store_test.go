package appliancestate

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

func TestPrivateDurabilityCorruptionAndLocks(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "state")
	os.Mkdir(dir, 0700)
	s, e := Open(dir)
	if e != nil {
		t.Fatal(e)
	}
	if second, e := Open(dir); e == nil {
		second.Close()
		t.Fatal("concurrent writer")
	}
	if e = s.Save(struct {
		Sequence int `json:"sequence"`
	}{1}); e != nil {
		t.Fatal(e)
	}
	s.Close()
	s, e = Open(dir)
	if e != nil {
		t.Fatal(e)
	}
	var state struct {
		Sequence int `json:"sequence"`
	}
	if e = s.Load(&state); e != nil || state.Sequence != 1 {
		t.Fatal(e)
	}
	s.Close()
	path := filepath.Join(dir, "state.json")
	b, _ := os.ReadFile(path)
	var record map[string]any
	json.Unmarshal(b, &record)
	record["payload"].(map[string]any)["sequence"] = 2
	b, _ = json.Marshal(record)
	os.WriteFile(path, b, 0600)
	s, e = Open(dir)
	if e != nil {
		t.Fatal(e)
	}
	defer s.Close()
	if e = s.Load(&state); e == nil {
		t.Fatal("corrupt valid JSON accepted")
	}
}
func TestPendingIntentAdoptedOnlyWhenComplete(t *testing.T) {
	for _, complete := range []bool{false, true} {
		t.Run(map[bool]string{false: "truncated", true: "complete"}[complete], func(t *testing.T) {
			dir := filepath.Join(t.TempDir(), "state")
			os.Mkdir(dir, 0700)
			s, e := Open(dir)
			if e != nil {
				t.Fatal(e)
			}
			s.Save(struct {
				Sequence int `json:"sequence"`
			}{1})
			s.Close()
			b, _ := os.ReadFile(filepath.Join(dir, "state.json"))
			if !complete {
				b = b[:len(b)/2]
			}
			name := ".pending-01234567890123456789012345678901"
			os.WriteFile(filepath.Join(dir, name), b, 0600)
			s, e = Open(dir)
			if !complete {
				if e == nil {
					s.Close()
					t.Fatal("partial intent accepted")
				}
				if _, e = os.Stat(filepath.Join(dir, name)); e != nil {
					t.Fatal("partial discarded")
				}
				return
			}
			if e != nil {
				t.Fatal(e)
			}
			defer s.Close()
			if _, e = os.Stat(filepath.Join(dir, name)); !os.IsNotExist(e) {
				t.Fatal("intent not adopted")
			}
		})
	}
}
func TestUnsafeFilesDenied(t *testing.T) {
	for _, kind := range []string{"directory-mode", "symlink", "hardlink", "state-mode"} {
		t.Run(kind, func(t *testing.T) {
			dir := filepath.Join(t.TempDir(), "state")
			os.Mkdir(dir, 0700)
			s, e := Open(dir)
			if e != nil {
				t.Fatal(e)
			}
			s.Save(struct {
				Sequence int `json:"sequence"`
			}{1})
			s.Close()
			path := filepath.Join(dir, "state.json")
			switch kind {
			case "directory-mode":
				os.Chmod(dir, 0755)
			case "symlink":
				os.Rename(path, path+"-old")
				os.Symlink(path+"-old", path)
			case "hardlink":
				os.Link(path, filepath.Join(t.TempDir(), "linked"))
			case "state-mode":
				os.Chmod(path, 0644)
			}
			s, e = Open(dir)
			if e != nil {
				return
			}
			defer s.Close()
			var state struct {
				Sequence int `json:"sequence"`
			}
			if e = s.Load(&state); e == nil {
				t.Fatal("unsafe state accepted")
			}
		})
	}
}
