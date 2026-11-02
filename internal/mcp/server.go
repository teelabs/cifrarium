package mcp

import (
	"bufio"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"path/filepath"
)

type Request struct {
	JSONRPC string `json:"jsonrpc"`
	ID      any    `json:"id"`
	Method  string `json:"method"`
}
type Response struct {
	JSONRPC string `json:"jsonrpc"`
	ID      any    `json:"id"`
	Result  any    `json:"result,omitempty"`
	Error   any    `json:"error,omitempty"`
}
type Server struct{ Socket string }

func (s Server) Listen() error {
	if err := os.MkdirAll(filepath.Dir(s.Socket), 0700); err != nil {
		return err
	}
	_ = os.Remove(s.Socket)
	l, err := net.Listen("unix", s.Socket)
	if err != nil {
		return err
	}
	defer l.Close()
	if err := os.Chmod(s.Socket, 0600); err != nil {
		return err
	}
	for {
		c, err := l.Accept()
		if err != nil {
			return err
		}
		go handle(c)
	}
}
func handle(c net.Conn) {
	defer c.Close()
	scan := bufio.NewScanner(c)
	enc := json.NewEncoder(c)
	for scan.Scan() {
		var r Request
		if json.Unmarshal(scan.Bytes(), &r) != nil {
			continue
		}
		switch r.Method {
		case "initialize":
			_ = enc.Encode(Response{"2.0", r.ID, map[string]any{"name": "cifrarium", "version": "0.2.1"}, nil})
		case "status", "snapshot.plan", "restore.plan":
			_ = enc.Encode(Response{"2.0", r.ID, map[string]any{"readOnly": true, "method": r.Method}, nil})
		default:
			_ = enc.Encode(Response{"2.0", r.ID, nil, fmt.Sprintf("method %q is not available", r.Method)})
		}
	}
}
