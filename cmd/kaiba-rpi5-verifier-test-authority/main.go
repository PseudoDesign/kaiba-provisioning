package main

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"
	"unicode/utf8"

	"github.com/ams-tech/nixos-kaiba-network/provisioning/internal/provisioning/mtls"
	"github.com/ams-tech/nixos-kaiba-network/provisioning/internal/provisioning/releaseauthorization"
)

const (
	maxPrivateKeyFileBytes = 16 * 1024
	maxTLSCertificateBytes = 1024 * 1024
)

type serverConfig struct {
	listen              string
	adminSocket         string
	tlsCertificatePath  string
	tlsPrivateKeyPath   string
	authorityKeyPath    string
	authorityKeyID      string
	bootstrapPublicKey  ed25519.PublicKey
	binding             releaseauthorization.BootBinding
	challengeMaxAge     time.Duration
	authorizationMaxAge time.Duration
	maxOutstanding      int
}

type openedFileIdentity struct {
	device uint64
	inode  uint64
	size   int64
	mode   uint32
	uid    uint32
	gid    uint32
	links  uint64
	mtime  syscall.Timespec
	ctime  syscall.Timespec
}

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	if err := run(ctx, os.Args[1:]); err != nil {
		log.Fatalf("kaiba-rpi5-verifier-test-authority (NON-PRODUCTION): %v", err)
	}
}

func parseConfig(arguments []string, output io.Writer) (serverConfig, error) {
	flags := flag.NewFlagSet("kaiba-rpi5-verifier-test-authority", flag.ContinueOnError)
	flags.SetOutput(output)
	var config serverConfig
	var bootstrapPublicKey string
	flags.StringVar(&config.listen, "listen", "127.0.0.1:8443", "explicit IP address and TLS port")
	flags.StringVar(&config.adminSocket, "admin-socket", "", "clean absolute path for the mode-0600 Unix bootstrap-registration socket")
	flags.StringVar(&config.tlsCertificatePath, "tls-cert", "", "TLS server certificate PEM path")
	flags.StringVar(&config.tlsPrivateKeyPath, "tls-key", "", "TLS server private-key PEM path")
	flags.StringVar(&config.authorityKeyPath, "authority-key", "", "non-production Ed25519 PKCS#8 private-key PEM path")
	flags.StringVar(&config.authorityKeyID, "authority-key-id", "", "non-production authority public-key identifier")
	flags.StringVar(&bootstrapPublicKey, "bootstrap-public-key", "", "preloaded Ed25519 public key for the exact logical identity")
	flags.StringVar(&config.binding.LogicalIdentity, "logical-identity", "", "preauthorized logical test identity")
	flags.StringVar(&config.binding.Audience, "audience", "", "preauthorized verifier consumer audience")
	flags.Uint64Var(&config.binding.VerifierVersion, "verifier-version", 0, "preauthorized numeric stable-verifier version")
	flags.StringVar(&config.binding.PolicyDigest, "policy-digest", "", "preauthorized sha256 policy digest")
	flags.StringVar(&config.binding.ManifestDigest, "manifest-digest", "", "preauthorized sha256 delegated-manifest digest")
	flags.Uint64Var(&config.binding.SecurityEpoch, "security-epoch", 0, "preauthorized non-zero security epoch")
	flags.DurationVar(&config.challengeMaxAge, "challenge-max-age", 30*time.Second, "signed challenge maximum age (whole seconds, at most 5m)")
	flags.DurationVar(&config.authorizationMaxAge, "authorization-max-age", 15*time.Second, "signed authorization maximum age (whole seconds, at most 5m)")
	flags.IntVar(&config.maxOutstanding, "max-outstanding-challenges", releaseauthorization.DefaultOutstandingChallenges, "aggregate retained authorization and bootstrap-registration capacity (legacy flag name)")
	if err := flags.Parse(arguments); err != nil {
		return serverConfig{}, err
	}
	if flags.NArg() != 0 {
		return serverConfig{}, errors.New("unexpected positional arguments")
	}
	for name, value := range map[string]string{
		"--tls-cert": config.tlsCertificatePath, "--tls-key": config.tlsPrivateKeyPath,
		"--authority-key": config.authorityKeyPath, "--authority-key-id": config.authorityKeyID,
		"--admin-socket": config.adminSocket,
	} {
		if value == "" {
			return serverConfig{}, fmt.Errorf("%s is required", name)
		}
	}
	if err := mtls.ValidateListenAddress(config.listen, true); err != nil {
		return serverConfig{}, err
	}
	if err := releaseauthorization.ValidateAdminSocketPath(config.adminSocket); err != nil {
		return serverConfig{}, err
	}
	for name, path := range map[string]string{
		"--tls-cert":      config.tlsCertificatePath,
		"--tls-key":       config.tlsPrivateKeyPath,
		"--authority-key": config.authorityKeyPath,
	} {
		if err := validateCleanAbsoluteFilePath(path); err != nil {
			return serverConfig{}, fmt.Errorf("%s: %w", name, err)
		}
	}
	if err := config.binding.Validate(); err != nil {
		return serverConfig{}, fmt.Errorf("preauthorized binding: %w", err)
	}
	maximumAge := time.Duration(releaseauthorization.MaxProtocolAgeSeconds) * time.Second
	if config.challengeMaxAge <= 0 || config.challengeMaxAge%time.Second != 0 || config.challengeMaxAge > maximumAge {
		return serverConfig{}, errors.New("--challenge-max-age must be a whole number of seconds between 1s and 5m")
	}
	if config.authorizationMaxAge <= 0 || config.authorizationMaxAge%time.Second != 0 || config.authorizationMaxAge > maximumAge {
		return serverConfig{}, errors.New("--authorization-max-age must be a whole number of seconds between 1s and 5m")
	}
	if config.maxOutstanding < 1 || config.maxOutstanding > 65536 {
		return serverConfig{}, errors.New("--max-outstanding-challenges must be between 1 and 65536")
	}
	if bootstrapPublicKey != "" {
		publicKey, err := releaseauthorization.DecodePublicKey(bootstrapPublicKey)
		if err != nil {
			return serverConfig{}, fmt.Errorf("--bootstrap-public-key: %w", err)
		}
		config.bootstrapPublicKey = publicKey
	}
	return config, nil
}

func run(ctx context.Context, arguments []string) error {
	if ctx == nil {
		return errors.New("context is required")
	}
	config, err := parseConfig(arguments, os.Stderr)
	if err != nil {
		return err
	}
	authorityPrivateKey, err := loadAuthorityPrivateKey(config.authorityKeyPath)
	if err != nil {
		return err
	}
	defer func() { clearBytes(authorityPrivateKey) }()
	tlsCertificate, err := loadTLSCertificate(config.tlsCertificatePath, config.tlsPrivateKeyPath)
	if err != nil {
		return err
	}
	bindingPolicy, err := releaseauthorization.NewExactBindingPolicy(config.binding)
	if err != nil {
		return err
	}
	authority, err := releaseauthorization.NewNonProductionAuthority(releaseauthorization.NonProductionAuthorityConfig{
		AuthorityKeyID: config.authorityKeyID, SigningKey: authorityPrivateKey,
		ChallengeMaxAge: config.challengeMaxAge, AuthorizationMaxAge: config.authorizationMaxAge,
		MaxOutstandingChallenges: config.maxOutstanding, BindingPolicy: bindingPolicy,
	})
	if err != nil {
		return err
	}
	clearBytes(authorityPrivateKey)
	authorityPrivateKey = nil
	defer authority.Close()
	if len(config.bootstrapPublicKey) != 0 {
		if err := authority.RegisterBootstrapKey(config.binding.LogicalIdentity, config.bootstrapPublicKey); err != nil {
			return err
		}
	}
	listener, err := net.Listen("tcp", config.listen)
	if err != nil {
		return fmt.Errorf("listen: %w", err)
	}
	adminListener, err := listenProtectedAdminSocket(config.adminSocket)
	if err != nil {
		_ = listener.Close()
		return err
	}
	tlsConfig := &tls.Config{
		MinVersion: tls.VersionTLS13, MaxVersion: tls.VersionTLS13,
		Certificates: []tls.Certificate{tlsCertificate},
	}
	listener = tls.NewListener(listener, tlsConfig)
	targetServer := &http.Server{
		Addr: config.listen, Handler: releaseauthorization.NonProductionHandler(authority),
		TLSConfig: tlsConfig, ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout: 10 * time.Second, WriteTimeout: 10 * time.Second,
		IdleTimeout: 30 * time.Second, MaxHeaderBytes: 8 * 1024,
	}
	adminServer := &http.Server{
		Handler:           releaseauthorization.NonProductionAdminHandler(authority),
		ConnContext:       releaseauthorization.NonProductionAdminConnContext,
		ReadHeaderTimeout: 2 * time.Second, ReadTimeout: 5 * time.Second,
		WriteTimeout: 5 * time.Second, IdleTimeout: 5 * time.Second,
		MaxHeaderBytes: 4 * 1024,
	}
	type serveResult struct {
		name string
		err  error
	}
	results := make(chan serveResult, 2)
	go func() { results <- serveResult{name: "TLS authority", err: targetServer.Serve(listener)} }()
	go func() { results <- serveResult{name: "Unix admin", err: adminServer.Serve(adminListener)} }()
	var first *serveResult
	select {
	case result := <-results:
		first = &result
	case <-ctx.Done():
	}
	shutdownContext, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	var shutdownErrors []error
	if err := targetServer.Shutdown(shutdownContext); err != nil {
		shutdownErrors = append(shutdownErrors, fmt.Errorf("shutdown TLS authority: %w", err))
		_ = targetServer.Close()
	}
	if err := adminServer.Shutdown(shutdownContext); err != nil {
		shutdownErrors = append(shutdownErrors, fmt.Errorf("shutdown Unix admin: %w", err))
		_ = adminServer.Close()
	}
	remaining := 2
	if first != nil {
		remaining = 1
		if first.err != nil && !errors.Is(first.err, http.ErrServerClosed) {
			shutdownErrors = append(shutdownErrors, fmt.Errorf("%s server: %w", first.name, first.err))
		}
	}
	for index := 0; index < remaining; index++ {
		result := <-results
		if result.err != nil && !errors.Is(result.err, http.ErrServerClosed) {
			shutdownErrors = append(shutdownErrors, fmt.Errorf("%s server: %w", result.name, result.err))
		}
	}
	return errors.Join(shutdownErrors...)
}

func listenProtectedAdminSocket(path string) (*net.UnixListener, error) {
	if err := releaseauthorization.ValidateAdminSocketPath(path); err != nil {
		return nil, err
	}
	parent := filepath.Dir(path)
	if err := requireOwnerControlledDirectory(parent); err != nil {
		return nil, fmt.Errorf("admin socket parent: %w", err)
	}
	if _, err := os.Lstat(path); err == nil {
		return nil, errors.New("admin socket path already exists")
	} else if !errors.Is(err, os.ErrNotExist) {
		return nil, fmt.Errorf("inspect admin socket path: %w", err)
	}
	previousUmask := syscall.Umask(0o177)
	listener, err := net.ListenUnix("unix", &net.UnixAddr{Name: path, Net: "unix"})
	syscall.Umask(previousUmask)
	if err != nil {
		return nil, fmt.Errorf("listen on Unix admin socket: %w", err)
	}
	listener.SetUnlinkOnClose(true)
	if err := os.Chmod(path, 0o600); err != nil {
		_ = listener.Close()
		return nil, fmt.Errorf("set admin socket permissions: %w", err)
	}
	info, err := os.Lstat(path)
	if err != nil || info.Mode()&os.ModeSocket == 0 || info.Mode().Perm() != 0o600 || !ownedByEffectiveUser(info) {
		_ = listener.Close()
		return nil, errors.New("admin socket is not an owner-controlled mode-0600 Unix socket")
	}
	return listener, nil
}

func loadAuthorityPrivateKey(path string) (ed25519.PrivateKey, error) {
	encoded, err := readRegularFileNoFollow(path, maxPrivateKeyFileBytes, true)
	if err != nil {
		return nil, fmt.Errorf("authority private key: %w", err)
	}
	defer clearBytes(encoded)
	block, remainder := pem.Decode(encoded)
	if block == nil || block.Type != "PRIVATE KEY" || len(bytes.TrimSpace(remainder)) != 0 {
		return nil, errors.New("authority private key must contain exactly one PKCS#8 PRIVATE KEY PEM block")
	}
	defer clearBytes(block.Bytes)
	parsed, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("parse authority PKCS#8 private key: %w", err)
	}
	privateKey, ok := parsed.(ed25519.PrivateKey)
	if !ok || len(privateKey) != ed25519.PrivateKeySize {
		return nil, errors.New("authority private key is not Ed25519")
	}
	result := append(ed25519.PrivateKey(nil), privateKey...)
	clearBytes(privateKey)
	return result, nil
}

func loadTLSCertificate(certificatePath, privateKeyPath string) (tls.Certificate, error) {
	certificatePEM, err := readRegularFileNoFollow(certificatePath, maxTLSCertificateBytes, false)
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("TLS certificate: %w", err)
	}
	privateKeyPEM, err := readRegularFileNoFollow(privateKeyPath, maxPrivateKeyFileBytes, true)
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("TLS private key: %w", err)
	}
	defer clearBytes(privateKeyPEM)
	certificate, err := tls.X509KeyPair(certificatePEM, privateKeyPEM)
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("load TLS certificate and key: %w", err)
	}
	return certificate, nil
}

func readRegularFileNoFollow(path string, maximumBytes int64, private bool) ([]byte, error) {
	file, identity, err := openAbsoluteNoFollow(path, false)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	if private && identity.mode&0o077 != 0 {
		return nil, errors.New("private key file must not be accessible by group or others")
	}
	if private && identity.uid != uint32(os.Geteuid()) {
		return nil, errors.New("private key file must be owned by the effective user")
	}
	if private && identity.links != 1 {
		return nil, errors.New("private key file must have exactly one hard link")
	}
	if identity.size <= 0 || identity.size > maximumBytes {
		return nil, errors.New("file has an invalid size")
	}
	encoded, err := io.ReadAll(io.LimitReader(file, maximumBytes+1))
	if err != nil {
		clearBytes(encoded)
		return nil, fmt.Errorf("read file: %w", err)
	}
	if int64(len(encoded)) != identity.size {
		clearBytes(encoded)
		return nil, errors.New("file changed size while reading")
	}
	current, err := statOpenedFile(int(file.Fd()))
	if err != nil || current != identity {
		clearBytes(encoded)
		return nil, errors.New("file identity or metadata changed while reading")
	}
	return encoded, nil
}

func requireOwnerControlledDirectory(path string) error {
	directory, identity, err := openAbsoluteNoFollow(path, true)
	if err != nil {
		return err
	}
	defer directory.Close()
	if identity.uid != uint32(os.Geteuid()) || identity.mode&0o022 != 0 {
		return errors.New("directory must be owned by the effective user and not writable by group or others")
	}
	return nil
}

func openAbsoluteNoFollow(path string, directory bool) (*os.File, openedFileIdentity, error) {
	if path == string(filepath.Separator) {
		if !directory {
			return nil, openedFileIdentity{}, errors.New("file path must not be the filesystem root")
		}
	} else if err := validateCleanAbsoluteFilePath(path); err != nil {
		return nil, openedFileIdentity{}, err
	}
	descriptor, err := syscall.Open("/", syscall.O_RDONLY|syscall.O_CLOEXEC|syscall.O_NOFOLLOW|syscall.O_DIRECTORY, 0)
	if err != nil {
		return nil, openedFileIdentity{}, fmt.Errorf("open filesystem root: %w", err)
	}
	current := os.NewFile(uintptr(descriptor), "/")
	if current == nil {
		_ = syscall.Close(descriptor)
		return nil, openedFileIdentity{}, errors.New("wrap filesystem root descriptor")
	}
	var components []string
	if path != string(filepath.Separator) {
		components = strings.Split(strings.TrimPrefix(path, string(filepath.Separator)), string(filepath.Separator))
	}
	for index, component := range components {
		last := index == len(components)-1
		flags := syscall.O_RDONLY | syscall.O_CLOEXEC | syscall.O_NOFOLLOW
		if !last || directory {
			flags |= syscall.O_DIRECTORY
		} else {
			flags |= syscall.O_NONBLOCK
		}
		nextDescriptor, err := syscall.Openat(int(current.Fd()), component, flags, 0)
		if err != nil {
			current.Close()
			return nil, openedFileIdentity{}, fmt.Errorf("open path component %q without following symlinks: %w", component, err)
		}
		next := os.NewFile(uintptr(nextDescriptor), component)
		if next == nil {
			_ = syscall.Close(nextDescriptor)
			current.Close()
			return nil, openedFileIdentity{}, errors.New("wrap opened path component descriptor")
		}
		current.Close()
		current = next
	}
	identity, err := statOpenedFile(int(current.Fd()))
	if err != nil {
		current.Close()
		return nil, openedFileIdentity{}, err
	}
	wantedType := uint32(syscall.S_IFREG)
	if directory {
		wantedType = syscall.S_IFDIR
	}
	if identity.mode&syscall.S_IFMT != wantedType || identity.mode&0o7000 != 0 {
		current.Close()
		return nil, openedFileIdentity{}, errors.New("path has the wrong file type or unsupported special mode bits")
	}
	if !directory {
		if err := syscall.SetNonblock(int(current.Fd()), false); err != nil {
			current.Close()
			return nil, openedFileIdentity{}, fmt.Errorf("set regular file descriptor blocking: %w", err)
		}
	}
	return current, identity, nil
}

func statOpenedFile(descriptor int) (openedFileIdentity, error) {
	var stat syscall.Stat_t
	if err := syscall.Fstat(descriptor, &stat); err != nil {
		return openedFileIdentity{}, err
	}
	return openedFileIdentity{
		device: uint64(stat.Dev), inode: stat.Ino, size: stat.Size, mode: stat.Mode,
		uid: stat.Uid, gid: stat.Gid, links: uint64(stat.Nlink), mtime: stat.Mtim, ctime: stat.Ctim,
	}, nil
}

func ownedByEffectiveUser(info os.FileInfo) bool {
	stat, ok := info.Sys().(*syscall.Stat_t)
	return ok && stat.Uid == uint32(os.Geteuid())
}

func validateCleanAbsoluteFilePath(path string) error {
	if path == "" || !filepath.IsAbs(path) || filepath.Clean(path) != path || path == string(filepath.Separator) ||
		strings.IndexByte(path, 0) >= 0 || !utf8.ValidString(path) {
		return errors.New("path must be a clean absolute file path")
	}
	return nil
}

func clearBytes(value []byte) {
	for index := range value {
		value[index] = 0
	}
}
