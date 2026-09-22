//go:build linux

package deviceenrollment

import (
	"fmt"
	"os"
	"strings"
	"syscall"
)

func checkStorage(s *store, c Config, r Runtime) error {
	if c.ProtectedVolume == "" {
		return nil // Explicit process-only software rehearsal.
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
	b, e := os.ReadFile(fmt.Sprintf("/sys/dev/block/%d:%d/dm/uuid", major, minor))
	prefix := "CRYPT-LUKS2-" + strings.ReplaceAll(uuid, "-", "") + "-"
	if e != nil || !strings.HasPrefix(string(b), prefix) || len(strings.TrimSpace(string(b))) <= len(prefix) {
		return ErrStorage
	}
	b, e = os.ReadFile("/proc/swaps")
	if e != nil || !strings.HasPrefix(string(b), "Filename") || len(strings.Split(strings.TrimSpace(string(b)), "\n")) != 1 {
		return ErrStorage
	}
	return nil
}
