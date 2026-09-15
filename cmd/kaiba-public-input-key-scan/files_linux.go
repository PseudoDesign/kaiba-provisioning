//go:build linux

package main

import (
	"errors"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"unicode/utf8"
)

type fileIdentity struct {
	device, inode uint64
	size          int64
	mode          uint32
	mtime, ctime  syscall.Timespec
}

func identityOf(file *os.File) (fileIdentity, error) {
	var value syscall.Stat_t
	if err := syscall.Fstat(int(file.Fd()), &value); err != nil {
		return fileIdentity{}, err
	}
	return fileIdentity{uint64(value.Dev), value.Ino, value.Size, value.Mode, value.Mtim, value.Ctim}, nil
}

func openInput(path string) (*os.File, fileIdentity, error) {
	if !utf8.ValidString(path) || path == "" || path == "/" || !filepath.IsAbs(path) || filepath.Clean(path) != path || strings.ContainsRune(path, 0) || path == "/dev" || strings.HasPrefix(path, "/dev/") {
		return nil, fileIdentity{}, errors.New("input must be a clean absolute path outside /dev")
	}
	fd, err := syscall.Open("/", syscall.O_RDONLY|syscall.O_DIRECTORY|syscall.O_CLOEXEC, 0)
	if err != nil {
		return nil, fileIdentity{}, errors.New("open input filesystem root failed")
	}
	current := os.NewFile(uintptr(fd), "/")
	for index, part := range strings.Split(strings.TrimPrefix(path, "/"), "/") {
		last := index == strings.Count(strings.TrimPrefix(path, "/"), "/")
		flags := syscall.O_CLOEXEC | syscall.O_NOFOLLOW
		if last {
			flags |= 0x200000
		} else {
			flags |= syscall.O_RDONLY | syscall.O_DIRECTORY | syscall.O_NONBLOCK
		}
		nextFD, openErr := syscall.Openat(int(current.Fd()), part, flags, 0)
		closeErr := current.Close()
		if openErr != nil {
			return nil, fileIdentity{}, errors.New("input path must not contain symlinks or unsupported components")
		}
		current = os.NewFile(uintptr(nextFD), part)
		if closeErr != nil {
			current.Close()
			return nil, fileIdentity{}, errors.New("close input ancestor failed")
		}
	}
	defer current.Close()
	before, err := identityOf(current)
	if err != nil || before.mode&syscall.S_IFMT != syscall.S_IFREG || before.mode&07000 != 0 || before.size < 0 || before.size == int64(^uint64(0)>>1) {
		return nil, fileIdentity{}, errors.New("input must be an ordinary regular file")
	}
	// O_PATH inspected the final node without opening devices/FIFOs for I/O.
	// Reopen only that process-owned descriptor after verifying its file type.
	reader, err := os.OpenFile("/proc/self/fd/"+strconv.FormatUint(uint64(current.Fd()), 10), os.O_RDONLY|syscall.O_CLOEXEC|syscall.O_NONBLOCK, 0)
	if err != nil {
		return nil, fileIdentity{}, errors.New("open pinned regular input failed")
	}
	opened, err := identityOf(reader)
	if err != nil || opened != before {
		reader.Close()
		return nil, fileIdentity{}, errors.New("input changed while opening")
	}
	return reader, before, nil
}
