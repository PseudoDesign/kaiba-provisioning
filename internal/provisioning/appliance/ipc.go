package appliance

import (
	"context"
	w "github.com/ams-tech/nixos-kaiba-network/provisioning/internal/appliancewire"
	"io"
	"net"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"syscall"
	"time"
)

type Snapshot struct {
	Receipt *w.Receipt `json:"receipt,omitempty"`
	Offer   *w.Offer   `json:"offer,omitempty"`
}

func (x *Executor) Snapshot() (Snapshot, error) {
	if x.state.Active == nil {
		return Snapshot{}, nil
	}
	o := x.state.Active.Offer
	r, e := x.Status()
	if e != nil {
		return Snapshot{Offer: &o}, e
	}
	return Snapshot{Receipt: &r, Offer: &o}, nil
}

type LocalExecutor interface {
	Snapshot() (Snapshot, error)
	Begin(Request) (w.Receipt, error)
	Activate(w.Signed) (w.Receipt, error)
	Confirm() (w.Receipt, error)
	Reconcile() (w.Receipt, error)
}
type ipcRequest struct {
	Action  string    `json:"action"`
	Request *Request  `json:"request,omitempty"`
	Lease   *w.Signed `json:"lease,omitempty"`
}
type ipcResponse struct {
	Snapshot *Snapshot  `json:"snapshot,omitempty"`
	Receipt  *w.Receipt `json:"receipt,omitempty"`
	Error    string     `json:"error,omitempty"`
}
type IPCServer struct {
	stopped  atomic.Bool
	workers  sync.WaitGroup
	listener *net.UnixListener
	executor *Executor
	uid      uint32
	lock     *os.File
	mu       sync.Mutex
}

func peer(conn *net.UnixConn) (*syscall.Ucred, error) {
	raw, e := conn.SyscallConn()
	if e != nil {
		return nil, e
	}
	var cred *syscall.Ucred
	var inner error
	e = raw.Control(func(fd uintptr) {
		cred, inner = syscall.GetsockoptUcred(int(fd), syscall.SOL_SOCKET, syscall.SO_PEERCRED)
	})
	if e != nil {
		return nil, e
	}
	return cred, inner
}

// OpenIPC requires a root-owned 0750 directory and socket group fixed by the
// installation profile. Only the exact dedicated agent UID is a caller role.
func OpenIPC(path string, uid, gid uint32, executor *Executor) (*IPCServer, error) {
	if os.Geteuid() != 0 || uid == 0 || executor == nil || !filepath.IsAbs(path) || path != "/run/kaiba-appliance/update.sock" {
		return nil, ErrDenied
	}
	parent := filepath.Dir(path)
	fd, e := syscall.Open(parent, syscall.O_DIRECTORY|syscall.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_CLOEXEC, 0)
	if e != nil {
		return nil, ErrDenied
	}
	dir := os.NewFile(uintptr(fd), parent)
	defer dir.Close()
	st, e := dir.Stat()
	if e != nil || st.Mode().Perm() != 0750 || st.Sys().(*syscall.Stat_t).Uid != 0 || st.Sys().(*syscall.Stat_t).Gid != gid {
		return nil, ErrDenied
	}
	fd, e = syscall.Openat(int(dir.Fd()), "ipc.lock", syscall.O_RDWR|syscall.O_CREAT|syscall.O_NOFOLLOW|syscall.O_CLOEXEC, 0600)
	if e != nil {
		return nil, ErrDenied
	}
	lock := os.NewFile(uintptr(fd), "ipc.lock")
	st, e = lock.Stat()
	if e != nil || !st.Mode().IsRegular() || st.Mode().Perm() != 0600 || st.Sys().(*syscall.Stat_t).Uid != 0 || st.Sys().(*syscall.Stat_t).Nlink != 1 || syscall.Flock(fd, syscall.LOCK_EX|syscall.LOCK_NB) != nil {
		lock.Close()
		return nil, ErrDenied
	}
	if existing, e := os.Lstat(path); e == nil {
		stat := existing.Sys().(*syscall.Stat_t)
		if existing.Mode()&os.ModeSocket == 0 || existing.Mode().Perm() != 0660 || stat.Uid != 0 || stat.Gid != gid {
			lock.Close()
			return nil, ErrDenied
		}
		if e = os.Remove(path); e != nil {
			lock.Close()
			return nil, e
		}
	} else if !os.IsNotExist(e) {
		lock.Close()
		return nil, ErrDenied
	}
	listener, e := net.ListenUnix("unix", &net.UnixAddr{Name: path, Net: "unix"})
	if e != nil {
		lock.Close()
		return nil, e
	}
	listener.SetUnlinkOnClose(false)
	if os.Chown(path, 0, int(gid)) != nil || os.Chmod(path, 0660) != nil {
		listener.Close()
		lock.Close()
		return nil, ErrDenied
	}
	return &IPCServer{listener: listener, executor: executor, uid: uid, lock: lock}, nil
}
func (s *IPCServer) Close() {
	s.stopped.Store(true)
	s.listener.Close()
	s.workers.Wait()
	if s.lock != nil {
		s.lock.Close()
	}
}
func (s *IPCServer) Serve(ctx context.Context) error {
	if ctx == nil {
		return ErrDenied
	}
	ctx, cancel := context.WithCancel(ctx)
	defer func() { s.stopped.Store(true); cancel(); s.workers.Wait() }()
	slots := make(chan struct{}, 2)
	go func() { <-ctx.Done(); s.stopped.Store(true); s.listener.Close() }()
	for {
		conn, e := s.listener.AcceptUnix()
		if e != nil {
			if ctx.Err() != nil {
				return ctx.Err()
			}
			return e
		}
		select {
		case slots <- struct{}{}:
			s.workers.Add(1)
			go func() {
				defer s.workers.Done()
				defer func() { <-slots }()
				s.serve(conn)
			}()
		default:
			conn.Close()
		}
	}
}
func (s *IPCServer) serve(conn *net.UnixConn) {
	defer conn.Close()
	conn.SetReadDeadline(time.Now().Add(10 * time.Second))
	cred, e := peer(conn)
	if e != nil || cred.Uid != s.uid {
		return
	}
	b, e := io.ReadAll(io.LimitReader(conn, w.MaxBytes+1))
	if e != nil || len(b) > w.MaxBytes {
		return
	}
	var q ipcRequest
	if w.Decode(b, &q) != nil {
		return
	}
	conn.SetReadDeadline(time.Time{})
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.stopped.Load() {
		return
	}
	var response ipcResponse
	var r w.Receipt
	switch q.Action {
	case "snapshot":
		if q.Request != nil || q.Lease != nil {
			e = ErrDenied
		} else {
			snapshot, err := s.executor.Snapshot()
			response.Snapshot = &snapshot
			e = err
		}
	case "begin":
		if q.Request == nil || q.Lease != nil {
			e = ErrDenied
		} else {
			r, e = s.executor.Begin(*q.Request)
			response.Receipt = &r
		}
	case "activate":
		if q.Lease == nil || q.Request != nil {
			e = ErrDenied
		} else {
			r, e = s.executor.Activate(*q.Lease)
			response.Receipt = &r
		}
	case "confirm":
		if q.Request != nil || q.Lease != nil {
			e = ErrDenied
		} else {
			r, e = s.executor.Confirm()
			response.Receipt = &r
		}
	case "reconcile":
		if q.Request != nil || q.Lease != nil {
			e = ErrDenied
		} else {
			r, e = s.executor.Reconcile()
			response.Receipt = &r
		}
	default:
		e = ErrDenied
	}
	if e != nil {
		switch e {
		case ErrDeferred:
			response.Error = "deferred"
		case ErrReconcile:
			response.Error = "reconciliation"
		default:
			response.Error = "denied"
		}
		response.Receipt = nil
	}
	conn.SetWriteDeadline(time.Now().Add(10 * time.Second))
	raw, e := w.Encode(response)
	if e == nil {
		conn.Write(raw)
	}
}

type IPCClient struct{ Path string }

func (c *IPCClient) call(q ipcRequest) (ipcResponse, error) { return c.callPeer(q, 0) }
func (c *IPCClient) callPeer(q ipcRequest, uid uint32) (ipcResponse, error) {
	var out ipcResponse
	conn, e := net.DialUnix("unix", nil, &net.UnixAddr{Name: c.Path, Net: "unix"})
	if e != nil {
		return out, ErrDeferred
	}
	defer conn.Close()
	timeout := 30 * time.Minute
	if q.Action == "snapshot" {
		timeout = 10 * time.Second
	}
	conn.SetDeadline(time.Now().Add(timeout))
	cred, e := peer(conn)
	if e != nil || cred.Uid != uid {
		return out, ErrDenied
	}
	raw, e := w.Encode(q)
	if e != nil {
		return out, ErrDenied
	}
	if _, e = conn.Write(raw); e != nil {
		return out, ErrDeferred
	}
	conn.CloseWrite()
	b, e := io.ReadAll(io.LimitReader(conn, w.MaxBytes+1))
	if e != nil || len(b) > w.MaxBytes || w.Decode(b, &out) != nil {
		return out, ErrDenied
	}
	switch out.Error {
	case "":
		return out, nil
	case "deferred":
		return out, ErrDeferred
	case "reconciliation":
		return out, ErrReconcile
	default:
		return out, ErrDenied
	}
}
func (c *IPCClient) Snapshot() (Snapshot, error) {
	out, e := c.call(ipcRequest{Action: "snapshot"})
	if out.Snapshot == nil {
		return Snapshot{}, ErrReconcile
	}
	if out.Snapshot.Offer != nil && out.Snapshot.Offer.Validate(time.Time{}, false) != nil {
		return Snapshot{}, ErrReconcile
	}
	if out.Snapshot.Receipt != nil && out.Snapshot.Receipt.Validate() != nil {
		return Snapshot{}, ErrReconcile
	}
	return *out.Snapshot, e
}
func (c *IPCClient) receipt(q ipcRequest) (w.Receipt, error) {
	out, e := c.call(q)
	if e != nil {
		return w.Receipt{}, e
	}
	if out.Receipt == nil || out.Receipt.Validate() != nil {
		return w.Receipt{}, ErrReconcile
	}
	return *out.Receipt, nil
}
func (c *IPCClient) Begin(q Request) (w.Receipt, error) {
	return c.receipt(ipcRequest{Action: "begin", Request: &q})
}
func (c *IPCClient) Activate(l w.Signed) (w.Receipt, error) {
	return c.receipt(ipcRequest{Action: "activate", Lease: &l})
}
func (c *IPCClient) Confirm() (w.Receipt, error)   { return c.receipt(ipcRequest{Action: "confirm"}) }
func (c *IPCClient) Reconcile() (w.Receipt, error) { return c.receipt(ipcRequest{Action: "reconcile"}) }
