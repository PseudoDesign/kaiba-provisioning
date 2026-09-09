//go:build linux

package stableverifier

import (
	"errors"
	"fmt"
	"os"
	"strings"
	"syscall"
	"unsafe"
)

const (
	snapshotMemfdCloseOnExec  = 0x0001
	snapshotMemfdAllowSealing = 0x0002
	snapshotFcntlAddSeals     = 1033
	snapshotFcntlGetSeals     = 1034
	snapshotSealSeal          = 0x0001
	snapshotSealShrink        = 0x0002
	snapshotSealGrow          = 0x0004
	snapshotSealWrite         = 0x0008
)

func newSnapshotFile(name string) (*os.File, error) {
	if name == "" || strings.IndexByte(name, 0) >= 0 {
		return nil, errors.New("verified snapshot name is invalid")
	}
	encoded := append([]byte(name), 0)
	descriptor, _, errno := syscall.Syscall(
		snapshotMemfdCreateSyscall,
		uintptr(unsafe.Pointer(&encoded[0])),
		uintptr(snapshotMemfdCloseOnExec|snapshotMemfdAllowSealing),
		0,
	)
	if errno != 0 {
		return nil, fmt.Errorf("create verified in-memory snapshot: %w", errno)
	}
	file := os.NewFile(descriptor, name)
	if file == nil {
		_ = syscall.Close(int(descriptor))
		return nil, errors.New("construct verified in-memory snapshot")
	}
	return file, nil
}

func sealSnapshotFile(file *os.File) error {
	if file == nil {
		return errors.New("verified snapshot is required")
	}
	seals := uintptr(snapshotSealSeal | snapshotSealShrink | snapshotSealGrow | snapshotSealWrite)
	_, _, errno := syscall.Syscall(syscall.SYS_FCNTL, file.Fd(), snapshotFcntlAddSeals, seals)
	if errno != 0 {
		return fmt.Errorf("seal verified in-memory snapshot: %w", errno)
	}
	return nil
}

func requireSealedSnapshotIdentity(file *os.File, expected fileIdentity) error {
	actual, err := statIdentity(int(file.Fd()))
	if err != nil {
		return err
	}
	if actual.device != expected.device || actual.inode != expected.inode || actual.size != expected.size ||
		actual.mode&syscall.S_IFMT != syscall.S_IFREG {
		return errors.New("verified snapshot identity changed")
	}
	required := uintptr(snapshotSealSeal | snapshotSealShrink | snapshotSealGrow | snapshotSealWrite)
	seals, _, errno := syscall.Syscall(syscall.SYS_FCNTL, file.Fd(), snapshotFcntlGetSeals, 0)
	if errno != 0 {
		return fmt.Errorf("read verified snapshot seals: %w", errno)
	}
	if seals&required != required {
		return errors.New("verified snapshot is not immutably sealed")
	}
	return nil
}
