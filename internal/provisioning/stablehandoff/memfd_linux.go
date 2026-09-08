//go:build linux

package stablehandoff

import (
	"errors"
	"fmt"
	"os"
	"syscall"
	"unsafe"
)

const (
	memfdCloseOnExec  = 0x0001
	memfdAllowSealing = 0x0002
	fcntlAddSeals     = 1033
	sealSeal          = 0x0001
	sealShrink        = 0x0002
	sealGrow          = 0x0004
	sealWrite         = 0x0008
)

func newSealableMemoryFile(name string) (*os.File, error) {
	if name == "" {
		return nil, errors.New("memory file name is required")
	}
	encoded := append([]byte(name), 0)
	fd, _, errno := syscall.Syscall(
		memfdCreateSyscall,
		uintptr(unsafe.Pointer(&encoded[0])),
		uintptr(memfdCloseOnExec|memfdAllowSealing),
		0,
	)
	if errno != 0 {
		return nil, fmt.Errorf("create in-memory handoff file: %w", errno)
	}
	file := os.NewFile(fd, name)
	if file == nil {
		_ = syscall.Close(int(fd))
		return nil, errors.New("construct in-memory handoff file")
	}
	return file, nil
}

func sealMemoryFile(file *os.File) error {
	if file == nil {
		return errors.New("memory file is required")
	}
	seals := uintptr(sealSeal | sealShrink | sealGrow | sealWrite)
	_, _, errno := syscall.Syscall(syscall.SYS_FCNTL, file.Fd(), fcntlAddSeals, seals)
	if errno != 0 {
		return fmt.Errorf("seal in-memory handoff file: %w", errno)
	}
	return nil
}
