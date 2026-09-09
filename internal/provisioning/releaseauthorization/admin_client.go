package releaseauthorization

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"mime"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"time"
	"unicode/utf8"
)

const DefaultAdminClientTimeout = 2 * time.Second

// NonProductionAdminClient registers ephemeral bootstrap public keys over the
// filesystem-protected Unix socket. It cannot reach the target-facing TLS
// listener and carries no private key material.
type NonProductionAdminClient struct {
	socketPath string
	httpClient *http.Client
}

func NewNonProductionAdminClient(socketPath string, timeout time.Duration) (*NonProductionAdminClient, error) {
	if err := ValidateAdminSocketPath(socketPath); err != nil {
		return nil, err
	}
	if timeout == 0 {
		timeout = DefaultAdminClientTimeout
	}
	if timeout <= 0 || timeout > 10*time.Second {
		return nil, invalid("admin client timeout must be between 1ns and 10s")
	}
	transport := &http.Transport{
		Proxy: nil, DisableCompression: true, DisableKeepAlives: true,
		DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			info, err := inspectAdminSocket(socketPath)
			if err != nil {
				return nil, err
			}
			dialer := net.Dialer{Timeout: timeout}
			connection, err := dialer.DialContext(ctx, "unix", socketPath)
			if err != nil {
				return nil, err
			}
			current, err := inspectAdminSocket(socketPath)
			if err != nil || !sameSocketIdentity(info, current) || !unixPeerIsEffectiveUser(connection) {
				_ = connection.Close()
				return nil, errors.New("non-production admin socket identity or peer changed during connection")
			}
			return connection, nil
		},
	}
	return &NonProductionAdminClient{
		socketPath: socketPath,
		httpClient: &http.Client{
			Transport: transport, Timeout: timeout,
			CheckRedirect: func(_ *http.Request, _ []*http.Request) error {
				return errors.New("non-production admin redirects are forbidden")
			},
		},
	}, nil
}

func (client *NonProductionAdminClient) RegisterBootstrap(ctx context.Context, registration BootstrapRegistration) error {
	if client == nil || client.httpClient == nil {
		return invalid("admin client is required")
	}
	if ctx == nil {
		return invalid("context is required")
	}
	encoded, err := registration.CanonicalJSON()
	if err != nil {
		return err
	}
	request, err := http.NewRequestWithContext(
		ctx, http.MethodPost, "http://unix"+BootstrapRegistrationEndpoint, bytes.NewReader(encoded),
	)
	if err != nil {
		return err
	}
	request.Header.Set("Content-Type", "application/json")
	response, err := client.httpClient.Do(request)
	if err != nil {
		return fmt.Errorf("register non-production bootstrap key: %w", err)
	}
	defer response.Body.Close()
	data, err := io.ReadAll(io.LimitReader(response.Body, MaxDocumentBytes+1))
	if err != nil {
		return fmt.Errorf("read non-production admin response: %w", err)
	}
	if len(data) > MaxDocumentBytes {
		return invalid("admin response exceeds the allowed size")
	}
	if response.StatusCode == http.StatusNoContent {
		if len(data) != 0 {
			return invalid("bootstrap registration success response must be empty")
		}
		return nil
	}
	mediaType, _, err := mime.ParseMediaType(response.Header.Get("Content-Type"))
	if err != nil || mediaType != "application/json" || len(data) == 0 {
		return fmt.Errorf("non-production admin server returned unparseable HTTP %d response", response.StatusCode)
	}
	remote, err := parseErrorResponse(data, response.StatusCode)
	if err != nil {
		return fmt.Errorf("non-production admin server returned unparseable HTTP %d response: %w", response.StatusCode, err)
	}
	return remote
}

func (client *NonProductionAdminClient) CloseIdleConnections() {
	if client != nil && client.httpClient != nil {
		client.httpClient.CloseIdleConnections()
	}
}

func ValidateAdminSocketPath(socketPath string) error {
	if socketPath == "" || !filepath.IsAbs(socketPath) || filepath.Clean(socketPath) != socketPath ||
		socketPath == string(filepath.Separator) || strings.IndexByte(socketPath, 0) >= 0 || !utf8.ValidString(socketPath) {
		return invalid("admin socket path must be a clean absolute file path")
	}
	if len(socketPath) > 100 {
		return invalid("admin socket path exceeds 100 bytes")
	}
	return nil
}

func inspectAdminSocket(socketPath string) (os.FileInfo, error) {
	if err := ValidateAdminSocketPath(socketPath); err != nil {
		return nil, err
	}
	parentPath := filepath.Dir(socketPath)
	resolvedParent, err := filepath.EvalSymlinks(parentPath)
	if err != nil || resolvedParent != parentPath {
		return nil, errors.New("non-production admin socket parent path must exist without symlinks")
	}
	descriptor, err := syscall.Open(
		parentPath, syscall.O_RDONLY|syscall.O_CLOEXEC|syscall.O_NOFOLLOW|syscall.O_DIRECTORY, 0,
	)
	if err != nil {
		return nil, fmt.Errorf("open non-production admin socket parent: %w", err)
	}
	parent := os.NewFile(uintptr(descriptor), parentPath)
	if parent == nil {
		_ = syscall.Close(descriptor)
		return nil, errors.New("wrap non-production admin socket parent descriptor")
	}
	parentInfo, statErr := parent.Stat()
	closeErr := parent.Close()
	if statErr != nil || closeErr != nil || !ownerControlledDirectory(parentInfo) {
		return nil, errors.New("non-production admin socket parent must be owner-controlled")
	}
	info, err := os.Lstat(socketPath)
	if err != nil {
		return nil, fmt.Errorf("inspect non-production admin socket: %w", err)
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || info.Mode()&os.ModeSocket == 0 || info.Mode().Perm() != 0o600 || stat.Uid != uint32(os.Geteuid()) {
		return nil, errors.New("non-production admin socket must be an owner-controlled mode-0600 Unix socket")
	}
	return info, nil
}

func ownerControlledDirectory(info os.FileInfo) bool {
	stat, ok := info.Sys().(*syscall.Stat_t)
	return ok && info.IsDir() && info.Mode().Perm()&0o022 == 0 && stat.Uid == uint32(os.Geteuid())
}

func sameSocketIdentity(left, right os.FileInfo) bool {
	return left != nil && right != nil && os.SameFile(left, right) && left.Mode() == right.Mode()
}

func unixPeerIsEffectiveUser(connection net.Conn) bool {
	if connection == nil || connection.RemoteAddr() == nil || connection.RemoteAddr().Network() != "unix" {
		return false
	}
	systemConnection, ok := connection.(syscall.Conn)
	if !ok {
		return false
	}
	raw, err := systemConnection.SyscallConn()
	if err != nil {
		return false
	}
	var credential *syscall.Ucred
	var socketError error
	if err := raw.Control(func(descriptor uintptr) {
		credential, socketError = syscall.GetsockoptUcred(int(descriptor), syscall.SOL_SOCKET, syscall.SO_PEERCRED)
	}); err != nil || socketError != nil || credential == nil {
		return false
	}
	return credential.Uid == uint32(os.Geteuid())
}
