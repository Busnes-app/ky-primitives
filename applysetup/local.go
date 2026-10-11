package applysetup

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/Busnes-app/ky-primitives/keyfile"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"sync"
	"time"
)

// StartLocal exposes setup only over a private filesystem socket. The product callback
// validates its own payload and owns all changes. Restart is the product's graceful-stop
// request; a workload controller restarts it with the committed configuration.
func StartLocal(ctx context.Context, socket string, apply func(context.Context, []byte, bool) (Report, error), restart func()) (func() error, error) {
	// A noncanonical path (".." after a symlink) can bind outside the checked directory.
	if !filepath.IsAbs(socket) || socket != filepath.Clean(socket) {
		return nil, errors.New("setup socket path must be absolute and canonical")
	}
	if len(socket) > maxSocketPath {
		return nil, fmt.Errorf("setup socket path exceeds the %d-byte Unix limit; shorten the data directory", maxSocketPath)
	}
	dir := filepath.Dir(socket)
	// Another user able to modify any ancestor could redirect the chmod and bind below.
	if err := keyfile.RequireTrustedAncestry(dir); err != nil {
		return nil, errors.New("setup socket directory has an ancestor other users can modify")
	}
	if err := os.MkdirAll(dir, 0700); err != nil {
		return nil, errors.New("cannot create private setup directory")
	}
	if err := keyfile.RequirePrivateDirectory(dir); err != nil {
		return nil, errors.New("setup socket requires a private owned directory")
	}
	if info, err := os.Lstat(socket); err == nil {
		if info.Mode()&os.ModeSocket == 0 {
			return nil, errors.New("setup socket path is occupied by a non-socket")
		}
		conn, err := net.DialTimeout("unix", socket, time.Second)
		if err == nil {
			conn.Close()
			return nil, errors.New("another product process owns the setup socket")
		}
		// The private parent excludes other users. Only a refused connection identifies a
		// stale socket; permissions and timeout failures remain errors.
		if !staleSocket(err) {
			return nil, errors.New("existing setup socket cannot be inspected")
		}
		if err := os.Remove(socket); err != nil {
			return nil, errors.New("cannot remove stale owned setup socket")
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return nil, errors.New("cannot inspect setup socket")
	}
	listener, err := net.Listen("unix", socket)
	if err != nil {
		return nil, errors.New("cannot bind setup socket")
	}
	if err := os.Chmod(socket, 0600); err != nil {
		listener.Close()
		return nil, errors.New("cannot protect setup socket")
	}
	var mutation sync.Mutex
	mux := http.NewServeMux()
	mux.HandleFunc("POST /setup", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.RawQuery != "" && r.URL.RawQuery != "check=true" {
			http.Error(w, "invalid setup request", 400)
			return
		}
		raw, err := io.ReadAll(io.LimitReader(r.Body, MaxBundleBytes+1))
		if err != nil || len(raw) > MaxBundleBytes {
			http.Error(w, "invalid setup request", 400)
			return
		}
		if !mutation.TryLock() {
			http.Error(w, "setup in progress", 409)
			return
		}
		defer mutation.Unlock()
		callCtx, cancel := context.WithTimeout(r.Context(), 30*time.Second)
		defer cancel()
		report, err := apply(callCtx, raw, r.URL.RawQuery == "check=true")
		if err != nil { // Keep arbitrary product/database errors out of the transport.
			http.Error(w, "setup refused; check product configuration locally", 409)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		report.Write(w)
	})
	mux.HandleFunc("POST /restart", func(w http.ResponseWriter, r *http.Request) {
		if restart == nil || r.URL.RawQuery != "" {
			http.Error(w, "restart unsupported", 409)
			return
		}
		if !mutation.TryLock() {
			http.Error(w, "setup in progress", 409)
			return
		}
		defer mutation.Unlock()
		w.WriteHeader(http.StatusAccepted)
		if f, ok := w.(http.Flusher); ok {
			f.Flush()
		}
		go restart()
	})
	server := &http.Server{Handler: mux, ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 30 * time.Second, WriteTimeout: 30 * time.Second, MaxHeaderBytes: 4096}
	done := make(chan struct{})
	go func() { defer close(done); _ = server.Serve(listener) }()
	go func() {
		select {
		case <-ctx.Done():
			_ = server.Close()
		case <-done:
		}
	}()
	var once sync.Once
	closeServer := func() error {
		var err error
		once.Do(func() {
			stop, cancel := context.WithTimeout(context.WithoutCancel(ctx), 30*time.Second)
			defer cancel()
			err = server.Shutdown(stop)
			if err != nil {
				_ = server.Close()
			}
			<-done
		})
		return err
	}
	return closeServer, nil
}
func DecodeRaw(raw []byte, dest any) error {
	if len(raw) > MaxBundleBytes {
		return errors.New("setup bundle exceeds limit")
	}
	d := json.NewDecoder(bytes.NewReader(raw))
	d.DisallowUnknownFields()
	if d.Decode(dest) != nil || d.Decode(new(any)) != io.EOF {
		return errors.New("invalid setup JSON")
	}
	return nil
}
func localClient(socket string) *http.Client {
	return &http.Client{Timeout: 30 * time.Second, Transport: &http.Transport{Proxy: nil, DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, "unix", socket)
	}}, CheckRedirect: func(*http.Request, []*http.Request) error { return errors.New("setup redirects refused") }}
}
func CallLocal(ctx context.Context, socket string, raw []byte, check bool) (Report, error) {
	if len(raw) > MaxBundleBytes {
		return Report{}, errors.New("setup bundle exceeds limit")
	}
	endpoint := "http://container/setup"
	if check {
		endpoint += "?check=true"
	}
	req, err := http.NewRequestWithContext(ctx, "POST", endpoint, bytes.NewReader(raw))
	if err != nil {
		return Report{}, errors.New("invalid setup request")
	}
	req.Header.Set("Content-Type", "application/json")
	client := localClient(socket)
	defer client.CloseIdleConnections()
	res, err := client.Do(req)
	if err != nil {
		return Report{}, errors.New("product setup socket unavailable")
	}
	defer res.Body.Close()
	if res.StatusCode != 200 {
		return Report{}, errors.New("product setup refused or is busy")
	}
	b, err := io.ReadAll(io.LimitReader(res.Body, MaxBundleBytes+1))
	if err != nil || len(b) > MaxBundleBytes {
		return Report{}, errors.New("invalid product setup response")
	}
	var report Report
	if json.Unmarshal(b, &report) != nil || report.Schema != ReportSchema {
		return Report{}, errors.New("invalid product setup report")
	}
	return report, nil
}
func RequestRestart(ctx context.Context, socket string) error {
	req, err := http.NewRequestWithContext(ctx, "POST", "http://container/restart", nil)
	if err != nil {
		return err
	}
	client := localClient(socket)
	defer client.CloseIdleConnections()
	res, err := client.Do(req)
	if err != nil {
		return errors.New("cannot request product activation")
	}
	defer res.Body.Close()
	if res.StatusCode != http.StatusAccepted {
		return errors.New("product activation refused")
	}
	return nil
}
