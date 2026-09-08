//go:build linux

package stableverifier

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"syscall"
	"unicode/utf8"

	"context"

	"github.com/ams-tech/nixos-kaiba-network/provisioning/internal/provisioning/bundle"
)

type fileIdentity struct {
	device uint64
	inode  uint64
	size   int64
	mode   uint32
	mtime  syscall.Timespec
	ctime  syscall.Timespec
}

func validateAbsolutePath(value string) error {
	if value == "" || value == string(filepath.Separator) || !filepath.IsAbs(value) || filepath.Clean(value) != value ||
		strings.IndexByte(value, 0) >= 0 || !utf8.ValidString(value) {
		return errors.New("path must be a clean absolute UTF-8 path other than /")
	}
	return nil
}

func openAbsolute(path string, directory bool) (*os.File, fileIdentity, error) {
	if err := validateAbsolutePath(path); err != nil {
		return nil, fileIdentity{}, err
	}
	rootFD, err := syscall.Open("/", syscall.O_RDONLY|syscall.O_CLOEXEC|syscall.O_NOFOLLOW|syscall.O_DIRECTORY, 0)
	if err != nil {
		return nil, fileIdentity{}, fmt.Errorf("open filesystem root: %w", err)
	}
	current := os.NewFile(uintptr(rootFD), "/")
	if current == nil {
		_ = syscall.Close(rootFD)
		return nil, fileIdentity{}, errors.New("construct filesystem root handle")
	}
	components := strings.Split(strings.TrimPrefix(path, "/"), "/")
	for index, component := range components {
		last := index == len(components)-1
		flags := syscall.O_RDONLY | syscall.O_CLOEXEC | syscall.O_NOFOLLOW
		if !last || directory {
			flags |= syscall.O_DIRECTORY
		} else {
			flags |= syscall.O_NONBLOCK
		}
		fd, err := syscall.Openat(int(current.Fd()), component, flags, 0)
		if err != nil {
			current.Close()
			return nil, fileIdentity{}, fmt.Errorf("open component %q without following symbolic links: %w", component, err)
		}
		next := os.NewFile(uintptr(fd), component)
		if next == nil {
			_ = syscall.Close(fd)
			current.Close()
			return nil, fileIdentity{}, fmt.Errorf("construct handle for component %q", component)
		}
		current.Close()
		current = next
	}
	identity, err := statIdentity(int(current.Fd()))
	if err != nil {
		current.Close()
		return nil, fileIdentity{}, err
	}
	if directory {
		if identity.mode&syscall.S_IFMT != syscall.S_IFDIR {
			current.Close()
			return nil, fileIdentity{}, errors.New("path is not a directory")
		}
	} else {
		if identity.mode&syscall.S_IFMT != syscall.S_IFREG {
			current.Close()
			return nil, fileIdentity{}, errors.New("path is not a regular file")
		}
		if err := syscall.SetNonblock(int(current.Fd()), false); err != nil {
			current.Close()
			return nil, fileIdentity{}, fmt.Errorf("clear nonblocking mode: %w", err)
		}
	}
	if identity.mode&07000 != 0 {
		current.Close()
		return nil, fileIdentity{}, errors.New("path has unsupported special permission bits")
	}
	return current, identity, nil
}

func statIdentity(fd int) (fileIdentity, error) {
	var stat syscall.Stat_t
	if err := syscall.Fstat(fd, &stat); err != nil {
		return fileIdentity{}, err
	}
	return fileIdentity{
		device: uint64(stat.Dev), inode: stat.Ino, size: stat.Size, mode: stat.Mode,
		mtime: stat.Mtim, ctime: stat.Ctim,
	}, nil
}

func sameIdentity(left, right fileIdentity) bool {
	return left == right
}

func requireSameOpenIdentity(file *os.File, expected fileIdentity) error {
	actual, err := statIdentity(int(file.Fd()))
	if err != nil {
		return err
	}
	if !sameIdentity(expected, actual) {
		return errors.New("open file identity or metadata changed")
	}
	return nil
}

func readAbsoluteRegular(path string, maximum int64) ([]byte, error) {
	file, identity, err := openAbsolute(path, false)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	if identity.size <= 0 || identity.size > maximum {
		return nil, fmt.Errorf("regular file size must be between 1 and %d bytes", maximum)
	}
	contents, err := io.ReadAll(io.LimitReader(file, maximum+1))
	if err != nil || int64(len(contents)) != identity.size {
		return nil, errors.New("regular file changed while reading")
	}
	if err := requireSameOpenIdentity(file, identity); err != nil {
		return nil, errors.New("regular file identity or metadata changed while reading")
	}
	return contents, nil
}

func readRegularAt(directory *os.File, name string, maximum int64) ([]byte, error) {
	file, identity, err := openRegularAt(directory, name)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	if identity.size <= 0 || identity.size > maximum {
		return nil, fmt.Errorf("regular file size must be between 1 and %d bytes", maximum)
	}
	contents, err := io.ReadAll(io.LimitReader(file, maximum+1))
	if err != nil || int64(len(contents)) != identity.size {
		return nil, errors.New("regular file changed while reading")
	}
	if err := requireSameOpenIdentity(file, identity); err != nil {
		return nil, errors.New("regular file identity or metadata changed while reading")
	}
	return contents, nil
}

func openRegularAt(directory *os.File, name string) (*os.File, fileIdentity, error) {
	if name == "" || filepath.Base(name) != name || strings.IndexByte(name, 0) >= 0 || !utf8.ValidString(name) {
		return nil, fileIdentity{}, errors.New("invalid fixed input file name")
	}
	fd, err := syscall.Openat(int(directory.Fd()), name, syscall.O_RDONLY|syscall.O_CLOEXEC|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
	if err != nil {
		return nil, fileIdentity{}, err
	}
	file := os.NewFile(uintptr(fd), name)
	if file == nil {
		_ = syscall.Close(fd)
		return nil, fileIdentity{}, errors.New("construct regular file handle")
	}
	identity, err := statIdentity(fd)
	if err != nil || identity.mode&syscall.S_IFMT != syscall.S_IFREG || identity.mode&07000 != 0 {
		file.Close()
		return nil, fileIdentity{}, errors.New("input is not an ordinary regular file")
	}
	if err := syscall.SetNonblock(fd, false); err != nil {
		file.Close()
		return nil, fileIdentity{}, err
	}
	return file, identity, nil
}

func openDirectoryAt(directory *os.File, name string) (*os.File, fileIdentity, error) {
	if name == "" || filepath.Base(name) != name || strings.IndexByte(name, 0) >= 0 || !utf8.ValidString(name) {
		return nil, fileIdentity{}, errors.New("invalid fixed directory name")
	}
	fd, err := syscall.Openat(int(directory.Fd()), name, syscall.O_RDONLY|syscall.O_CLOEXEC|syscall.O_NOFOLLOW|syscall.O_DIRECTORY, 0)
	if err != nil {
		return nil, fileIdentity{}, err
	}
	opened := os.NewFile(uintptr(fd), name)
	if opened == nil {
		_ = syscall.Close(fd)
		return nil, fileIdentity{}, errors.New("construct directory handle")
	}
	identity, err := statIdentity(fd)
	if err != nil || identity.mode&syscall.S_IFMT != syscall.S_IFDIR || identity.mode&07000 != 0 {
		opened.Close()
		return nil, fileIdentity{}, errors.New("input is not an ordinary directory")
	}
	return opened, identity, nil
}

func requireExactNames(directory *os.File, names []string) error {
	wanted := append([]string(nil), names...)
	for _, name := range wanted {
		if name == "" || filepath.Base(name) != name {
			return errors.New("invalid fixed directory entry name")
		}
	}
	sort.Strings(wanted)
	for index := 1; index < len(wanted); index++ {
		if wanted[index] == wanted[index-1] {
			return errors.New("fixed directory entry name is duplicated")
		}
	}
	if _, err := directory.Seek(0, 0); err != nil {
		return err
	}
	actual, err := directory.Readdirnames(-1)
	if err != nil {
		return err
	}
	sort.Strings(actual)
	if len(actual) != len(wanted) {
		return fmt.Errorf("directory must contain exactly %s", strings.Join(wanted, ", "))
	}
	for index := range wanted {
		if wanted[index] != actual[index] {
			return fmt.Errorf("directory must contain exactly %s", strings.Join(wanted, ", "))
		}
	}
	return nil
}

func verifyAndRetainAt(
	ctx context.Context,
	directory *os.File,
	name string,
	expectedDigest bundle.Digest,
	expectedSize uint64,
	maximum uint64,
	snapshot bool,
) (retainedFile, error) {
	if expectedSize == 0 || expectedSize > maximum {
		return retainedFile{}, fmt.Errorf("expected size must be between 1 and %d bytes", maximum)
	}
	file, identity, err := openRegularAt(directory, name)
	if err != nil {
		return retainedFile{}, err
	}
	var frozen *os.File
	failed := true
	defer func() {
		if failed {
			_ = file.Close()
			if frozen != nil {
				_ = frozen.Close()
			}
		}
	}()
	if identity.size < 0 || uint64(identity.size) != expectedSize {
		return retainedFile{}, fmt.Errorf("file size is %d, expected %d", identity.size, expectedSize)
	}
	if snapshot {
		frozen, err = newSnapshotFile("kaiba-verified-" + name)
		if err != nil {
			return retainedFile{}, err
		}
	}
	hash := sha256.New()
	buffer := make([]byte, 64*1024)
	var total uint64
	for {
		if err := ctx.Err(); err != nil {
			return retainedFile{}, err
		}
		read, readErr := file.Read(buffer)
		if read > 0 {
			total += uint64(read)
			if total > expectedSize {
				return retainedFile{}, errors.New("file grew while hashing")
			}
			_, _ = hash.Write(buffer[:read])
			if frozen != nil {
				written, writeErr := frozen.Write(buffer[:read])
				if writeErr != nil {
					return retainedFile{}, fmt.Errorf("snapshot verified file: %w", writeErr)
				}
				if written != read {
					return retainedFile{}, errors.New("snapshot verified file: short write")
				}
			}
		}
		if readErr == io.EOF {
			break
		}
		if readErr != nil {
			return retainedFile{}, readErr
		}
	}
	if total != expectedSize {
		return retainedFile{}, fmt.Errorf("hashed size is %d, expected %d", total, expectedSize)
	}
	if err := requireSameOpenIdentity(file, identity); err != nil {
		return retainedFile{}, errors.New("file identity or metadata changed while hashing")
	}
	actualDigest := bundle.Digest("sha256:" + hex.EncodeToString(hash.Sum(nil)))
	if actualDigest != expectedDigest {
		return retainedFile{}, fmt.Errorf("file digest is %s, expected %s", actualDigest, expectedDigest)
	}
	if frozen != nil {
		if err := sealSnapshotFile(frozen); err != nil {
			return retainedFile{}, err
		}
		if _, err := frozen.Seek(0, 0); err != nil {
			return retainedFile{}, fmt.Errorf("rewind verified snapshot: %w", err)
		}
		frozenIdentity, err := statIdentity(int(frozen.Fd()))
		if err != nil {
			return retainedFile{}, fmt.Errorf("inspect verified snapshot: %w", err)
		}
		if err := file.Close(); err != nil {
			return retainedFile{}, fmt.Errorf("close verified source file: %w", err)
		}
		failed = false
		return retainedFile{file: frozen, identity: frozenIdentity, immutableSnapshot: true}, nil
	}
	if _, err := file.Seek(0, 0); err != nil {
		return retainedFile{}, fmt.Errorf("rewind verified file: %w", err)
	}
	failed = false
	return retainedFile{file: file, identity: identity}, nil
}

func verifySlotMetadata(file *os.File, slotID string) error {
	if _, err := file.Seek(0, 0); err != nil {
		return fmt.Errorf("rewind slot metadata: %w", err)
	}
	contents, err := io.ReadAll(io.LimitReader(file, 4097))
	if err != nil {
		return fmt.Errorf("read slot metadata: %w", err)
	}
	if string(contents) != slotID+"\n" {
		return errors.New("slot metadata does not equal the manifest slot_id")
	}
	if _, err := file.Seek(0, 0); err != nil {
		return fmt.Errorf("rewind slot metadata: %w", err)
	}
	return nil
}

func readKernelCommandLine(file *os.File) (string, error) {
	if _, err := file.Seek(0, 0); err != nil {
		return "", fmt.Errorf("rewind kernel command line: %w", err)
	}
	contents, err := io.ReadAll(io.LimitReader(file, int64(componentMaximums[RoleKernelCommandLine])+1))
	if err != nil {
		return "", fmt.Errorf("read kernel command line: %w", err)
	}
	if len(contents) < 2 || len(contents) > int(componentMaximums[RoleKernelCommandLine]) || contents[len(contents)-1] != '\n' {
		return "", errors.New("kernel command line must be a non-empty LF-terminated file within the fixed bound")
	}
	commandLine := string(contents[:len(contents)-1])
	if strings.ContainsAny(commandLine, "\x00\r\n") {
		return "", errors.New("kernel command line contains NUL or an embedded line break")
	}
	if _, err := file.Seek(0, 0); err != nil {
		return "", fmt.Errorf("rewind kernel command line: %w", err)
	}
	return commandLine, nil
}

func duplicateRetained(source retainedFile) (*os.File, error) {
	var identityErr error
	if source.immutableSnapshot {
		identityErr = requireSealedSnapshotIdentity(source.file, source.identity)
	} else {
		identityErr = requireSameOpenIdentity(source.file, source.identity)
	}
	if identityErr != nil {
		return nil, errors.New("verified component changed before handoff")
	}
	fd, err := syscall.Dup(int(source.file.Fd()))
	if err != nil {
		return nil, fmt.Errorf("duplicate verified component handle: %w", err)
	}
	syscall.CloseOnExec(fd)
	duplicate := os.NewFile(uintptr(fd), source.metadata.Name)
	if duplicate == nil {
		_ = syscall.Close(fd)
		return nil, errors.New("construct duplicated verified component handle")
	}
	if _, err := duplicate.Seek(0, 0); err != nil {
		duplicate.Close()
		return nil, fmt.Errorf("rewind duplicated component: %w", err)
	}
	return duplicate, nil
}
