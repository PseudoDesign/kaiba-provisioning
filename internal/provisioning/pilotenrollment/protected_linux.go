//go:build linux

package pilotenrollment

import (
	"fmt"
	"io/fs"
	"os"
	"regexp"
	"strings"
	"syscall"
)

func checkStorage(s *store, c Config, r Runtime) error {
	if c.ProtectedVolume == "" {
		return ErrStorage
	}
	check := r.CheckStorage
	if check == nil {
		check = protectedFilesystem
	}
	if check(s.dir, c.ProtectedVolume) != nil {
		return ErrStorage
	}
	return nil
}

// This checks the pinned directory's current Linux mount, not a path supplied
// by a report or lsblk's heuristic TYPE. It is a development deployment guard,
// not proof of hardware key custody or protection from privileged software.
func protectedFilesystem(dir *os.File, uuid string) error {
	var st syscall.Stat_t
	var fs syscall.Statfs_t
	if syscall.Fstat(int(dir.Fd()), &st) != nil || syscall.Fstatfs(int(dir.Fd()), &fs) != nil || fs.Type != 0xef53 || fs.Flags&15 != 14 {
		return ErrStorage // Writable ext4 with nosuid,nodev,noexec.
	}
	// Linux's encoded dev_t layout (the same as sysmacros major/minor).
	major := (uint64(st.Dev)>>8)&0xfff | (uint64(st.Dev)>>32)&0xfffff000
	minor := uint64(st.Dev)&0xff | (uint64(st.Dev)>>12)&0xffffff00
	if encryptedBacking(os.DirFS("/sys"), fmt.Sprintf("%d:%d", major, minor), uuid) != nil {
		return ErrStorage
	}
	b, e := os.ReadFile("/proc/swaps")
	if e != nil || !strings.HasPrefix(string(b), "Filename") || len(strings.Split(strings.TrimSpace(string(b)), "\n")) != 1 {
		return ErrStorage
	}
	return nil
}

// Accept only a bounded single-parent LVM chain ending at the configured LUKS2
// mapping. Mixed backing devices, thin pools, loops and ambiguous paths fail
// closed. This observes kernel metadata; it never opens or changes a device.
func encryptedBacking(sys fs.FS, device, uuid string) error {
	seen := map[string]bool{}
	devicePattern := regexp.MustCompile(`^[0-9]+:[0-9]+$`)
	for depth := 0; depth < 8; depth++ {
		if !devicePattern.MatchString(device) || seen[device] {
			return ErrStorage
		}
		seen[device] = true
		base := "dev/block/" + device
		raw, e := fs.ReadFile(sys, base+"/dm/uuid")
		if e != nil {
			return ErrStorage
		}
		identity := strings.TrimSpace(string(raw))
		prefix := "CRYPT-LUKS2-" + strings.ReplaceAll(uuid, "-", "") + "-"
		if strings.HasPrefix(identity, prefix) && len(identity) > len(prefix) {
			return nil
		}
		if !strings.HasPrefix(identity, "LVM-") {
			return ErrStorage
		}
		children, e := fs.ReadDir(sys, base+"/slaves")
		if e != nil || len(children) != 1 {
			return ErrStorage
		}
		raw, e = fs.ReadFile(sys, base+"/slaves/"+children[0].Name()+"/dev")
		if e != nil {
			return ErrStorage
		}
		device = strings.TrimSpace(string(raw))
	}
	return ErrStorage
}
