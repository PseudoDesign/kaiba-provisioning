package fleetexport

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"

	"github.com/ams-tech/nixos-kaiba-network/provisioning/internal/provisioning/auditlog"
	"github.com/ams-tech/nixos-kaiba-network/provisioning/internal/provisioning/controlplane"
)

// ReadOnlyStore cannot initialize or save authority state, even accidentally.
// Missing files are errors, not an empty source authority.
type ReadOnlyStore struct{ Path string }

func (s ReadOnlyStore) Load() ([]byte, error) { return os.ReadFile(s.Path) }
func (s ReadOnlyStore) Save([]byte) error {
	return errors.New("fleet export cannot write authority state")
}

type diskControl struct{ path string }

func (r diskControl) GetTransaction(ctx context.Context, id string) (controlplane.Transaction, error) {
	service, err := controlplane.NewService(ReadOnlyStore{r.path})
	if err != nil {
		return controlplane.Transaction{}, err
	}
	return service.GetTransaction(ctx, id)
}

// FromStores uses the source services' own persisted-state validation, including
// audit chain validation. It opens control afresh for each bracketing read.
func FromStores(ctx context.Context, controlPath, auditPath, id string, p Policy) (Bundle, error) {
	audit, err := auditlog.NewService(ReadOnlyStore{auditPath})
	if err != nil {
		return Bundle{}, err
	}
	return Build(ctx, diskControl{controlPath}, audit, id, p)
}

// Save retains evidence first, then atomically publishes an immutable record.
// Retry compares exact bytes; it never replaces a different existing revision.
func (b Bundle) Save(root string) (string, error) {
	for role, data := range map[string][]byte{"control": b.ControlBytes, "audit": b.AuditBytes} {
		path := filepath.Join(root, "evidence", role, Digest(data)[7:]+".json")
		if err := writeImmutable(path, data); err != nil {
			return "", err
		}
	}
	data, err := b.JSON()
	if err != nil {
		return "", err
	}
	path := filepath.Join(root, "records", b.Record.RecordID, strconv.FormatUint(b.Record.Revision, 10)+".json")
	if err := writeImmutable(path, data); err != nil {
		return "", err
	}
	return path, nil
}
func writeImmutable(path string, data []byte) error {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0700); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(dir, ".fleet-export-*")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name())
	if _, err = tmp.Write(data); err != nil {
		tmp.Close()
		return err
	}
	if err = tmp.Sync(); err != nil {
		tmp.Close()
		return err
	}
	if err = tmp.Close(); err != nil {
		return err
	}
	if err = os.Link(tmp.Name(), path); err != nil {
		if !errors.Is(err, os.ErrExist) {
			return err
		}
		existing, readErr := os.ReadFile(path)
		if readErr != nil {
			return readErr
		}
		if !bytes.Equal(existing, data) {
			return fmt.Errorf("immutable export conflict: %s", path)
		}
	}
	directory, err := os.Open(dir)
	if err != nil {
		return err
	}
	defer directory.Close()
	return directory.Sync()
}
