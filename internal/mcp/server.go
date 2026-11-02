package mcp

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"path/filepath"
)

type Request struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      any             `json:"id"`
	Method  string          `json:"method"`
	Params  json.RawMessage `json:"params,omitempty"`
}
type Response struct {
	JSONRPC string `json:"jsonrpc"`
	ID      any    `json:"id"`
	Result  any    `json:"result,omitempty"`
	Error   any    `json:"error,omitempty"`
}
type Handler interface {
	Handle(context.Context, Request) (any, error)
}

type HandlerFunc func(context.Context, Request) (any, error)

func (f HandlerFunc) Handle(ctx context.Context, request Request) (any, error) {
	return f(ctx, request)
}

type Server struct {
	Socket  string
	Handler Handler
}

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
		go handle(c, s.Handler)
	}
}
func handle(c net.Conn, handler Handler) {
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
			_ = enc.Encode(Response{"2.0", r.ID, map[string]any{"name": "cifrarium", "version": "0.3.0"}, nil})
		case "status", "snapshot.plan", "restore.plan":
			if handler == nil {
				_ = enc.Encode(Response{"2.0", r.ID, nil, "daemon handler is unavailable"})
				continue
			}
			result, err := handler.Handle(context.Background(), r)
			if err != nil {
				_ = enc.Encode(Response{"2.0", r.ID, nil, err.Error()})
				continue
			}
			_ = enc.Encode(Response{"2.0", r.ID, result, nil})
		default:
			_ = enc.Encode(Response{"2.0", r.ID, nil, fmt.Sprintf("method %q is not available", r.Method)})
		}
	}
}
