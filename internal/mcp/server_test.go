package mcp

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestInitializeHandshake(t *testing.T) {
	socket := filepath.Join(t.TempDir(), "cifrarium.sock")
	done := make(chan struct{})
	go func() { _ = (Server{Socket: socket}).Listen(); close(done) }()
	var c net.Conn
	var err error
	for i := 0; i < 50; i++ {
		c, err = net.Dial("unix", socket)
		if err == nil {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	if _, err := c.Write([]byte(`{"jsonrpc":"2.0","id":1,"method":"initialize"}` + "\n")); err != nil {
		t.Fatal(err)
	}
	var response Response
	if err := json.NewDecoder(bufio.NewReader(c)).Decode(&response); err != nil {
		t.Fatal(err)
	}
	if response.Error != nil {
		t.Fatal(response.Error)
	}
	if response.Result == nil {
		t.Fatal("missing initialize result")
	}
	_ = os.Remove(socket)
}

func TestSocketIsPrivateAndMutationsAreRejected(t *testing.T) {
	socket := filepath.Join(t.TempDir(), "cifrarium.sock")
	go func() { _ = (Server{Socket: socket}).Listen() }()
	var c net.Conn
	var err error
	for i := 0; i < 50; i++ {
		c, err = net.Dial("unix", socket)
		if err == nil {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	info, err := os.Stat(socket)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0600 {
		t.Fatalf("socket mode=%o", info.Mode().Perm())
	}
	decoder := json.NewDecoder(bufio.NewReader(c))
	for id, method := range map[int]string{1: "snapshot", 2: "restore", 3: "upload"} {
		request := fmt.Sprintf(`{"jsonrpc":"2.0","id":%d,"method":"%s"}`+"\n", id, method)
		if _, err := c.Write([]byte(request)); err != nil {
			t.Fatal(err)
		}
		var response Response
		if err := decoder.Decode(&response); err != nil {
			t.Fatal(err)
		}
		if response.Error == nil {
			t.Fatalf("mutation %q was accepted", method)
		}
	}
}

func TestAllowedMethodsUseDaemonHandler(t *testing.T) {
	socket := filepath.Join(t.TempDir(), "cifrarium.sock")
	calls := make(chan string, 1)
	handler := HandlerFunc(func(_ context.Context, request Request) (any, error) {
		calls <- request.Method
		return map[string]any{
			"readOnly":                true,
			"requiresCliConfirmation": true,
			"plan":                    "capture allowlisted configuration",
		}, nil
	})
	go func() { _ = (Server{Socket: socket, Handler: handler}).Listen() }()
	c := dialSocket(t, socket)
	defer c.Close()
	if _, err := c.Write([]byte(`{"jsonrpc":"2.0","id":1,"method":"snapshot.plan"}` + "\n")); err != nil {
		t.Fatal(err)
	}
	var response Response
	if err := json.NewDecoder(bufio.NewReader(c)).Decode(&response); err != nil {
		t.Fatal(err)
	}
	if response.Error != nil {
		t.Fatal(response.Error)
	}
	result, ok := response.Result.(map[string]any)
	if !ok || result["plan"] != "capture allowlisted configuration" {
		t.Fatalf("unexpected plan result: %#v", response.Result)
	}
	select {
	case method := <-calls:
		if method != "snapshot.plan" {
			t.Fatalf("handler method=%q", method)
		}
	case <-time.After(time.Second):
		t.Fatal("daemon handler was not called")
	}
}

func dialSocket(t *testing.T, socket string) net.Conn {
	t.Helper()
	var c net.Conn
	var err error
	for i := 0; i < 50; i++ {
		c, err = net.Dial("unix", socket)
		if err == nil {
			return c
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatal(err)
	return nil
}
