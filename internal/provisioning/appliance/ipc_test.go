package appliance

import (
	"net"
	"os"
	"path/filepath"
	"sync"
	"testing"
)

func TestIPCExactPeerAndBoundedVocabulary(t *testing.T) {
	f := newFixture(t)
	x := f.open(t)
	defer x.Close()
	path := filepath.Join(t.TempDir(), "update.sock")
	listener, e := net.ListenUnix("unix", &net.UnixAddr{Name: path, Net: "unix"})
	if e != nil {
		t.Fatal(e)
	}
	defer listener.Close()
	server := &IPCServer{executor: x, uid: uint32(os.Geteuid())}
	var workers sync.WaitGroup
	serveOnce := func() {
		workers.Add(1)
		go func() {
			defer workers.Done()
			conn, e := listener.AcceptUnix()
			if e == nil {
				server.serve(conn)
			}
		}()
	}
	client := &IPCClient{Path: path}
	serveOnce()
	out, e := client.callPeer(ipcRequest{Action: "snapshot"}, uint32(os.Geteuid()))
	if e != nil || out.Snapshot == nil {
		t.Fatal("peer credentials", e)
	}
	serveOnce()
	if _, e = client.callPeer(ipcRequest{Action: "execute"}, uint32(os.Geteuid())); e != ErrDenied {
		t.Fatal("arbitrary action", e)
	}
	serveOnce()
	if _, e = client.callPeer(ipcRequest{Action: "snapshot", Request: &f.q}, uint32(os.Geteuid())); e != ErrDenied {
		t.Fatal("extra request on status", e)
	}
	workers.Wait()
	server.uid++
	serveOnce()
	if _, e = client.callPeer(ipcRequest{Action: "begin", Request: &f.q}, uint32(os.Geteuid())); e == nil {
		t.Fatal("wrong caller UID accepted")
	}
	if f.boot.trials != 0 || x.state.Active != nil {
		t.Fatal("denied requests dispatched")
	}
}
func TestIPCClientRequiresRootServer(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("unprivileged-server test requires nonroot test account")
	}
	path := filepath.Join(t.TempDir(), "update.sock")
	listener, e := net.ListenUnix("unix", &net.UnixAddr{Name: path, Net: "unix"})
	if e != nil {
		t.Fatal(e)
	}
	defer listener.Close()
	go func() {
		conn, e := listener.AcceptUnix()
		if e == nil {
			defer conn.Close()
			conn.Write([]byte(`{"snapshot":{}}`))
		}
	}()
	if _, e = (&IPCClient{Path: path}).Snapshot(); e != ErrReconcile {
		t.Fatal("unprivileged server accepted", e)
	}
}
