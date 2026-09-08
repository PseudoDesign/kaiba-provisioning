//go:build linux

// kaiba-rpi5-one-boot-prove is the deliberately non-production released-stage
// client for the Raspberry Pi 5 stable-verifier spike. It proves receipt of a
// one-boot private key and destroys the named key file before sending proof.
package main

import (
	"context"
	"crypto/ed25519"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/ams-tech/nixos-kaiba-network/provisioning/internal/provisioning/releaseauthorization"
)

const (
	defaultAuthorizationPath = "/run/kaiba/boot-authorization.json"
	defaultOneBootKeyPath    = "/run/kaiba/one-boot-ed25519.pk8"
	defaultRequestTimeout    = 5 * time.Second
	maxCABytes               = 1024 * 1024
	maxPrivateKeyBytes       = 16 * 1024
)

type config struct {
	authorityURL       string
	authorityCAPath    string
	authorityKeyID     string
	authorityPublicKey ed25519.PublicKey
	authorizationPath  string
	oneBootKeyPath     string
	timeout            time.Duration
}

type pinnedPrivateKey struct {
	parent  *os.File
	file    *os.File
	leaf    string
	initial os.FileInfo
}

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	if err := run(ctx, os.Args[1:]); err != nil {
		log.Fatalf("kaiba-rpi5-one-boot-prove (NON-PRODUCTION): %v", err)
	}
}

func run(ctx context.Context, arguments []string) error {
	if ctx == nil {
		return errors.New("context is required")
	}
	cfg, err := parseConfig(arguments, os.Stderr)
	if err != nil {
		return err
	}
	rootPool, err := loadCAPool(cfg.authorityCAPath)
	if err != nil {
		return fmt.Errorf("load explicit authority CA: %w", err)
	}
	client, err := releaseauthorization.NewNonProductionClient(releaseauthorization.NonProductionClientConfig{
		BaseURL: cfg.authorityURL, AuthorityKeyID: cfg.authorityKeyID,
		AuthorityPublicKey: cfg.authorityPublicKey,
		TLSConfig: &tls.Config{
			RootCAs: rootPool, MinVersion: tls.VersionTLS13, MaxVersion: tls.VersionTLS13,
		},
		Timeout: cfg.timeout,
	})
	if err != nil {
		return err
	}
	defer client.CloseIdleConnections()

	proof, err := prepareOneBootProof(
		cfg.authorizationPath, cfg.oneBootKeyPath, cfg.authorityKeyID, cfg.authorityPublicKey,
	)
	if err != nil {
		return err
	}
	requestContext, cancel := context.WithTimeout(ctx, cfg.timeout)
	defer cancel()
	if err := client.ProveOneBoot(requestContext, proof); err != nil {
		return fmt.Errorf("proof submission failed after the one-boot private key was removed: %w", err)
	}
	return nil
}

func parseConfig(arguments []string, output io.Writer) (config, error) {
	flags := flag.NewFlagSet("kaiba-rpi5-one-boot-prove", flag.ContinueOnError)
	flags.SetOutput(output)
	var cfg config
	var authorityPublicKey string
	flags.StringVar(&cfg.authorityURL, "authority-url", "", "non-production authorization HTTPS origin")
	flags.StringVar(&cfg.authorityCAPath, "authority-ca", "", "explicit authorization TLS CA PEM path")
	flags.StringVar(&cfg.authorityKeyID, "authority-key-id", "", "pinned authorization signing-key identifier")
	flags.StringVar(&authorityPublicKey, "authority-public-key", "", "pinned ed25519:<hex> authorization public key")
	flags.StringVar(&cfg.authorizationPath, "authorization", defaultAuthorizationPath, "canonical handoff authorization path")
	flags.StringVar(&cfg.oneBootKeyPath, "one-boot-key", defaultOneBootKeyPath, "one-boot Ed25519 PKCS#8 key path")
	flags.DurationVar(&cfg.timeout, "timeout", defaultRequestTimeout, "one-boot proof request timeout")
	if err := flags.Parse(arguments); err != nil {
		return config{}, err
	}
	if flags.NArg() != 0 {
		return config{}, errors.New("unexpected positional arguments")
	}
	for name, value := range map[string]string{
		"--authority-url": cfg.authorityURL, "--authority-ca": cfg.authorityCAPath,
		"--authority-key-id": cfg.authorityKeyID, "--authority-public-key": authorityPublicKey,
	} {
		if value == "" {
			return config{}, fmt.Errorf("%s is required", name)
		}
	}
	for name, path := range map[string]string{
		"--authority-ca":  cfg.authorityCAPath,
		"--authorization": cfg.authorizationPath,
		"--one-boot-key":  cfg.oneBootKeyPath,
	} {
		if err := validateCleanAbsolutePath(path); err != nil {
			return config{}, fmt.Errorf("%s: %w", name, err)
		}
	}
	if cfg.timeout <= 0 || cfg.timeout > 30*time.Second {
		return config{}, errors.New("--timeout must be positive and at most 30 seconds")
	}
	publicKey, err := releaseauthorization.DecodePublicKey(authorityPublicKey)
	if err != nil {
		return config{}, fmt.Errorf("--authority-public-key: %w", err)
	}
	cfg.authorityPublicKey = publicKey
	return cfg, nil
}

func prepareOneBootProof(
	authorizationPath string,
	oneBootKeyPath string,
	authorityKeyID string,
	authorityPublicKey ed25519.PublicKey,
) (releaseauthorization.OneBootProof, error) {
	encodedAuthorization, err := readRegularNoFollow(
		authorizationPath, int64(releaseauthorization.MaxDocumentBytes), false,
	)
	if err != nil {
		return releaseauthorization.OneBootProof{}, fmt.Errorf("read handoff authorization: %w", err)
	}
	defer clearBytes(encodedAuthorization)
	authorization, err := releaseauthorization.ParseAuthorization(encodedAuthorization)
	if err != nil {
		return releaseauthorization.OneBootProof{}, err
	}
	if err := releaseauthorization.VerifyAuthorizationSignature(
		authorization, authorityKeyID, authorityPublicKey,
	); err != nil {
		return releaseauthorization.OneBootProof{}, err
	}

	pinned, err := openPinnedPrivateKey(oneBootKeyPath)
	if err != nil {
		return releaseauthorization.OneBootProof{}, err
	}
	defer pinned.Close()
	encodedPrivateKey, err := pinned.Read(maxPrivateKeyBytes)
	if err != nil {
		return releaseauthorization.OneBootProof{}, err
	}
	defer clearBytes(encodedPrivateKey)
	privateKey, err := parseOneBootPrivateKey(encodedPrivateKey)
	if err != nil {
		return releaseauthorization.OneBootProof{}, err
	}
	// NewOneBootProof also consumes this buffer. The explicit defer protects
	// this boundary if that API changes and covers every error return here.
	defer clearBytes(privateKey)
	proof, err := releaseauthorization.NewOneBootProof(authorization, privateKey)
	if err != nil {
		return releaseauthorization.OneBootProof{}, err
	}
	if err := pinned.Remove(); err != nil {
		return releaseauthorization.OneBootProof{}, err
	}
	return proof, nil
}

func loadCAPool(path string) (*x509.CertPool, error) {
	contents, err := readRegularNoFollow(path, maxCABytes, false)
	if err != nil {
		return nil, err
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(contents) {
		return nil, errors.New("authority CA does not contain a PEM certificate")
	}
	return pool, nil
}

func parseOneBootPrivateKey(encoded []byte) (ed25519.PrivateKey, error) {
	parsed, err := x509.ParsePKCS8PrivateKey(encoded)
	if err != nil {
		return nil, fmt.Errorf("parse one-boot PKCS#8 private key: %w", err)
	}
	privateKey, ok := parsed.(ed25519.PrivateKey)
	if !ok || len(privateKey) != ed25519.PrivateKeySize {
		return nil, errors.New("one-boot private key is not Ed25519")
	}
	result := append(ed25519.PrivateKey(nil), privateKey...)
	clearBytes(privateKey)
	return result, nil
}

func openPinnedPrivateKey(path string) (*pinnedPrivateKey, error) {
	if err := validateCleanAbsolutePath(path); err != nil {
		return nil, err
	}
	parentPath := filepath.Dir(path)
	resolvedParent, err := filepath.EvalSymlinks(parentPath)
	if err != nil {
		return nil, fmt.Errorf("resolve one-boot key parent: %w", err)
	}
	if resolvedParent != parentPath {
		return nil, errors.New("one-boot key parent path must not contain symlinks")
	}
	parentFD, err := syscall.Open(
		parentPath, syscall.O_RDONLY|syscall.O_CLOEXEC|syscall.O_NOFOLLOW|syscall.O_DIRECTORY, 0,
	)
	if err != nil {
		return nil, fmt.Errorf("open one-boot key parent: %w", err)
	}
	parent := os.NewFile(uintptr(parentFD), parentPath)
	if parent == nil {
		_ = syscall.Close(parentFD)
		return nil, errors.New("wrap one-boot key parent descriptor")
	}
	parentInfo, err := parent.Stat()
	if err != nil {
		parent.Close()
		return nil, fmt.Errorf("inspect one-boot key parent: %w", err)
	}
	stat, ok := parentInfo.Sys().(*syscall.Stat_t)
	if !ok || !parentInfo.IsDir() || stat.Uid != uint32(os.Geteuid()) || parentInfo.Mode().Perm()&0o022 != 0 {
		parent.Close()
		return nil, errors.New("one-boot key parent must be an owner-controlled non-writable-by-others directory")
	}
	leaf := filepath.Base(path)
	fileFD, err := syscall.Openat(
		parentFD, leaf, syscall.O_RDONLY|syscall.O_CLOEXEC|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0,
	)
	if err != nil {
		parent.Close()
		return nil, fmt.Errorf("open one-boot private key without following symlinks: %w", err)
	}
	file := os.NewFile(uintptr(fileFD), leaf)
	if file == nil {
		_ = syscall.Close(fileFD)
		parent.Close()
		return nil, errors.New("wrap one-boot private-key descriptor")
	}
	info, err := file.Stat()
	if err != nil {
		file.Close()
		parent.Close()
		return nil, fmt.Errorf("inspect one-boot private key: %w", err)
	}
	stat, statOK := info.Sys().(*syscall.Stat_t)
	if !statOK || !info.Mode().IsRegular() || info.Mode().Perm()&0o077 != 0 ||
		stat.Uid != uint32(os.Geteuid()) || stat.Nlink != 1 {
		file.Close()
		parent.Close()
		return nil, errors.New("one-boot private key must be a singly linked owner-only regular file")
	}
	if err := syscall.SetNonblock(fileFD, false); err != nil {
		file.Close()
		parent.Close()
		return nil, fmt.Errorf("set one-boot private key descriptor blocking: %w", err)
	}
	return &pinnedPrivateKey{parent: parent, file: file, leaf: leaf, initial: info}, nil
}

func (pinned *pinnedPrivateKey) Read(maximum int64) ([]byte, error) {
	if pinned == nil || pinned.file == nil || maximum <= 0 || pinned.initial.Size() <= 0 || pinned.initial.Size() > maximum {
		return nil, errors.New("one-boot private key has an invalid size")
	}
	contents, err := io.ReadAll(io.LimitReader(pinned.file, maximum+1))
	if err != nil || int64(len(contents)) != pinned.initial.Size() {
		clearBytes(contents)
		return nil, errors.New("one-boot private key changed while reading")
	}
	current, err := pinned.file.Stat()
	if err != nil || !sameFileMetadata(pinned.initial, current) {
		clearBytes(contents)
		return nil, errors.New("one-boot private key identity or metadata changed while reading")
	}
	return contents, nil
}

func (pinned *pinnedPrivateKey) Remove() error {
	if pinned == nil || pinned.file == nil || pinned.parent == nil {
		return errors.New("one-boot private key is not pinned")
	}
	descriptor, err := syscall.Openat(
		int(pinned.parent.Fd()), pinned.leaf,
		syscall.O_RDONLY|syscall.O_CLOEXEC|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0,
	)
	if err != nil {
		return fmt.Errorf("reopen one-boot private key before removal: %w", err)
	}
	current := os.NewFile(uintptr(descriptor), pinned.leaf)
	if current == nil {
		_ = syscall.Close(descriptor)
		return errors.New("wrap re-opened one-boot private-key descriptor")
	}
	currentInfo, statErr := current.Stat()
	closeErr := current.Close()
	if statErr != nil || closeErr != nil || !sameFileMetadata(pinned.initial, currentInfo) {
		return errors.New("one-boot private key path changed before removal")
	}
	if err := syscall.Unlinkat(int(pinned.parent.Fd()), pinned.leaf); err != nil {
		return fmt.Errorf("remove one-boot private key: %w", err)
	}
	if descriptor, err := syscall.Openat(
		int(pinned.parent.Fd()), pinned.leaf,
		syscall.O_RDONLY|syscall.O_CLOEXEC|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0,
	); err == nil {
		_ = syscall.Close(descriptor)
		return errors.New("one-boot private key path still exists after removal")
	} else if !errors.Is(err, syscall.ENOENT) {
		return fmt.Errorf("verify one-boot private key removal: %w", err)
	}
	return nil
}

func (pinned *pinnedPrivateKey) Close() {
	if pinned == nil {
		return
	}
	if pinned.file != nil {
		_ = pinned.file.Close()
		pinned.file = nil
	}
	if pinned.parent != nil {
		_ = pinned.parent.Close()
		pinned.parent = nil
	}
}

func readRegularNoFollow(path string, maximum int64, private bool) ([]byte, error) {
	if err := validateCleanAbsolutePath(path); err != nil {
		return nil, err
	}
	parentPath := filepath.Dir(path)
	resolvedParent, err := filepath.EvalSymlinks(parentPath)
	if err != nil {
		return nil, fmt.Errorf("resolve file parent: %w", err)
	}
	if resolvedParent != parentPath {
		return nil, errors.New("file parent path must not contain symlinks")
	}
	descriptor, err := syscall.Open(path, syscall.O_RDONLY|syscall.O_CLOEXEC|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
	if err != nil {
		return nil, fmt.Errorf("open file without following symlinks: %w", err)
	}
	file := os.NewFile(uintptr(descriptor), path)
	if file == nil {
		_ = syscall.Close(descriptor)
		return nil, errors.New("wrap opened file descriptor")
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil || !info.Mode().IsRegular() || (private && info.Mode().Perm()&0o077 != 0) ||
		info.Size() <= 0 || info.Size() > maximum {
		return nil, errors.New("file identity, permissions, or size are invalid")
	}
	if err := syscall.SetNonblock(descriptor, false); err != nil {
		return nil, err
	}
	contents, err := io.ReadAll(io.LimitReader(file, maximum+1))
	if err != nil || int64(len(contents)) != info.Size() {
		clearBytes(contents)
		return nil, errors.New("file changed while reading")
	}
	current, err := file.Stat()
	if err != nil || !sameFileMetadata(info, current) {
		clearBytes(contents)
		return nil, errors.New("file identity or metadata changed while reading")
	}
	return contents, nil
}

func sameFileMetadata(left, right os.FileInfo) bool {
	if left == nil || right == nil || !os.SameFile(left, right) ||
		left.Mode() != right.Mode() || left.Size() != right.Size() || !left.ModTime().Equal(right.ModTime()) {
		return false
	}
	leftStat, leftOK := left.Sys().(*syscall.Stat_t)
	rightStat, rightOK := right.Sys().(*syscall.Stat_t)
	return leftOK && rightOK && leftStat.Uid == rightStat.Uid && leftStat.Gid == rightStat.Gid &&
		leftStat.Nlink == rightStat.Nlink && leftStat.Mtim == rightStat.Mtim && leftStat.Ctim == rightStat.Ctim
}

func validateCleanAbsolutePath(path string) error {
	if path == "" || !filepath.IsAbs(path) || filepath.Clean(path) != path ||
		path == string(filepath.Separator) || strings.IndexByte(path, 0) >= 0 {
		return errors.New("path must be a clean absolute file path")
	}
	return nil
}

func clearBytes(value []byte) {
	for index := range value {
		value[index] = 0
	}
}
