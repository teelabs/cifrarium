package rpc

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/teelabs/cifrarium/internal/limits"
)

func TestLocalRPCRequestAndResponse(t *testing.T) {
	socket := filepath.Join(t.TempDir(), "control.sock")
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	server, err := ListenUnix(socket, func(_ context.Context, request Request) (any, *Error) {
		if request.Method != "daemon.status" {
			return nil, &Error{Code: -32601, Message: "method not found"}
		}
		return map[string]any{"backend": "ready", "protocol": ProtocolVersion}, nil
	}, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer server.Close()
	go func() { _ = server.Serve(ctx) }()

	var result map[string]string
	callCtx, callCancel := context.WithTimeout(context.Background(), time.Second)
	defer callCancel()
	if err := Call(callCtx, socket, "daemon.status", nil, &result); err != nil {
		t.Fatal(err)
	}
	if result["backend"] != "ready" || result["protocol"] != ProtocolVersion {
		t.Fatalf("result = %#v", result)
	}
}

func TestUnixTransportSatisfiesPortableTransportContract(t *testing.T) {
	var _ Transport = UnixTransport{}
}

func TestLocalRPCUsesPrivateSocketAndStructuredErrors(t *testing.T) {
	socket := filepath.Join(t.TempDir(), "control.sock")
	server, err := ListenUnix(socket, func(context.Context, Request) (any, *Error) {
		return nil, &Error{Code: -32001, Message: "operation rejected", Data: map[string]any{"retryable": false}}
	}, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer server.Close()
	info, err := os.Stat(socket)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0600 {
		t.Fatalf("socket mode = %o; want 600", info.Mode().Perm())
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() { _ = server.Serve(ctx) }()

	err = Call(context.Background(), socket, "forbidden", nil, nil)
	var rpcErr *Error
	if !errors.As(err, &rpcErr) || rpcErr.Code != -32001 || rpcErr.Message != "operation rejected" {
		t.Fatalf("error = %#v; want structured RPC error", err)
	}
	if _, err := net.Dial("unix", socket); err != nil {
		t.Fatal(err)
	}
}

func TestLocalRPCDoesNotStealAnActiveEndpoint(t *testing.T) {
	socket := filepath.Join(t.TempDir(), "control.sock")
	first, err := ListenUnix(socket, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer first.Close()
	if _, err := ListenUnix(socket, nil, nil); err == nil || err.Error() != "RPC endpoint is already in use" {
		t.Fatalf("second listener error = %v; want active-endpoint rejection", err)
	}
}

func TestLocalRPCRemovesAStaleEndpoint(t *testing.T) {
	socket := filepath.Join(t.TempDir(), "control.sock")
	listener, err := net.Listen("unix", socket)
	if err != nil {
		t.Fatal(err)
	}
	if err := listener.Close(); err != nil {
		t.Fatal(err)
	}
	server, err := ListenUnix(socket, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer server.Close()
}

func TestLocalRPCRejectsMalformedJSON(t *testing.T) {
	socket := filepath.Join(t.TempDir(), "control.sock")
	server, err := ListenUnix(socket, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer server.Close()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() { _ = server.Serve(ctx) }()
	conn, err := net.Dial("unix", socket)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	if _, err := conn.Write([]byte("not-json\n")); err != nil {
		t.Fatal(err)
	}
	var response Response
	if err := json.NewDecoder(conn).Decode(&response); err != nil {
		t.Fatal(err)
	}
	if response.Error == nil || response.Error.Code != -32700 {
		t.Fatalf("response = %#v; want parse error", response)
	}
}

func TestLocalRPCNegotiatesProtocolVersion(t *testing.T) {
	socket := filepath.Join(t.TempDir(), "control.sock")
	server, err := ListenUnix(socket, func(context.Context, Request) (any, *Error) {
		return map[string]string{"ok": "yes"}, nil
	}, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer server.Close()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() { _ = server.Serve(ctx) }()

	conn, err := net.Dial("unix", socket)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	if _, err := fmt.Fprintf(conn, `{"jsonrpc":"2.0","id":"1","protocol":"cifrarium.control.v0","method":"status"}`+"\n"); err != nil {
		t.Fatal(err)
	}
	var response Response
	if err := json.NewDecoder(conn).Decode(&response); err != nil {
		t.Fatal(err)
	}
	if response.Error == nil || response.Error.Code != -32002 || response.Protocol != ProtocolVersion {
		t.Fatalf("response = %#v; want protocol negotiation error", response)
	}
}

func TestLocalRPCRejectsOversizedRequest(t *testing.T) {
	server, client := net.Pipe()
	defer client.Close()
	done := make(chan struct{})
	go func() {
		serveConn(context.Background(), server, nil)
		close(done)
	}()
	writeErr := make(chan error, 1)
	go func() {
		_, err := client.Write([]byte(strings.Repeat("x", limits.MaxMCPLineBytes+1) + "\n"))
		writeErr <- err
	}()
	var response Response
	if err := json.NewDecoder(client).Decode(&response); err != nil {
		t.Fatalf("oversized request did not receive an error response: %v", err)
	}
	if response.Error == nil || response.Error.Code != -32004 {
		t.Fatalf("response = %#v; want request-limit error", response)
	}
	_ = <-writeErr
	<-done
}

type pipeTransport struct{ conn net.Conn }

func (p pipeTransport) Listen(string) (net.Listener, error) { return nil, errors.New("not supported") }
func (p pipeTransport) DialContext(context.Context, string) (net.Conn, error) {
	return p.conn, nil
}

func TestLocalRPCCallCancellationClosesTheConnection(t *testing.T) {
	client, server := net.Pipe()
	defer server.Close()
	requestRead := make(chan struct{})
	serverDone := make(chan struct{})
	go func() {
		buf := make([]byte, 1024)
		_, _ = server.Read(buf)
		close(requestRead)
		<-serverDone
	}()
	defer close(serverDone)

	ctx, cancel := context.WithCancel(context.Background())
	callDone := make(chan error, 1)
	go func() {
		callDone <- CallWithTransport(pipeTransport{conn: client}, ctx, "pipe", "status", nil, nil)
	}()
	select {
	case <-requestRead:
	case <-time.After(time.Second):
		t.Fatal("RPC request was not sent")
	}
	cancel()
	select {
	case err := <-callDone:
		if err == nil {
			t.Fatal("cancelled RPC unexpectedly succeeded")
		}
	case <-time.After(time.Second):
		t.Fatal("RPC call did not honor cancellation")
	}
}
