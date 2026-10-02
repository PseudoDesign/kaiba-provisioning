//go:build linux

package campaignqualification

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"syscall"

	"github.com/ams-tech/nixos-kaiba-network/provisioning/internal/provisioning/bundle"
)

// FileAdmission consumes a capture exactly once in an existing private
// directory. It rejects symlink components and never resets or deletes an
// uncertain reservation. The admission authority owns this directory; an
// evidence submitter must not be allowed to replace it or erase its contents.
type FileAdmission struct{ Directory string }

func (ledger FileAdmission) Consume(session Session, result bundle.Digest) error {
	if err := session.Context.CaptureID.Validate(); err != nil {
		return err
	}
	if err := result.Validate(); err != nil {
		return err
	}
	if !filepath.IsAbs(ledger.Directory) || filepath.Clean(ledger.Directory) != ledger.Directory || ledger.Directory == "/" {
		return errors.New("admission requires a canonical absolute private directory")
	}
	directory, err := openPrivateDirectory(ledger.Directory)
	if err != nil {
		return err
	}
	defer syscall.Close(directory)
	name := strings.TrimPrefix(string(session.Context.CaptureID), "capture:") + ".json"
	fd, err := syscall.Openat(directory, name, syscall.O_WRONLY|syscall.O_CREAT|syscall.O_EXCL|syscall.O_NOFOLLOW|syscall.O_CLOEXEC, 0600)
	if errors.Is(err, syscall.EEXIST) {
		return errors.New("capture nonce already consumed; preserve and reconcile the existing admission")
	}
	if err != nil {
		return fmt.Errorf("reserve capture: %w", err)
	}
	file := os.NewFile(uintptr(fd), name)
	defer file.Close()
	encoded, err := json.Marshal(struct {
		Session      Session       `json:"session"`
		ResultDigest bundle.Digest `json:"result_digest"`
	}{session, result})
	if err != nil {
		return err
	}
	if _, err := file.Write(append(encoded, '\n')); err != nil {
		return fmt.Errorf("uncertain capture reservation: %w", err)
	}
	if err := file.Sync(); err != nil {
		return fmt.Errorf("uncertain capture reservation sync: %w", err)
	}
	if err := syscall.Fsync(directory); err != nil {
		return fmt.Errorf("uncertain capture directory sync: %w", err)
	}
	return nil
}

func openPrivateDirectory(path string) (int, error) {
	fd, err := syscall.Open("/", syscall.O_RDONLY|syscall.O_DIRECTORY|syscall.O_CLOEXEC, 0)
	if err != nil {
		return -1, err
	}
	for _, component := range strings.Split(strings.TrimPrefix(path, "/"), "/") {
		next, err := syscall.Openat(fd, component, syscall.O_RDONLY|syscall.O_DIRECTORY|syscall.O_NOFOLLOW|syscall.O_CLOEXEC, 0)
		syscall.Close(fd)
		if err != nil {
			return -1, err
		}
		fd = next
		var stat syscall.Stat_t
		if err := syscall.Fstat(fd, &stat); err != nil {
			syscall.Close(fd)
			return -1, err
		}
		if stat.Mode&0022 != 0 && stat.Mode&syscall.S_ISVTX == 0 {
			syscall.Close(fd)
			return -1, errors.New("admission directory has a writable non-sticky ancestor")
		}
	}
	var stat syscall.Stat_t
	if err := syscall.Fstat(fd, &stat); err != nil {
		syscall.Close(fd)
		return -1, err
	}
	if stat.Uid != uint32(os.Geteuid()) || stat.Mode&0777 != 0700 {
		syscall.Close(fd)
		return -1, errors.New("admission directory must be owned by the admission process and mode 0700")
	}
	return fd, nil
}
