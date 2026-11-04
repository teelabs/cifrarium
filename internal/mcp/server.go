package mcp

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"syscall"
	"time"

	"github.com/teelabs/cifrarium/internal/limits"
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
	Error   *Error `json:"error,omitempty"`
}

type Error struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
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
	Ready   func()
	Context context.Context
}

func (s Server) Listen() error {
	if err := os.MkdirAll(filepath.Dir(s.Socket), 0700); err != nil {
		return err
	}
	if info, err := os.Lstat(s.Socket); err == nil {
		if info.Mode()&os.ModeSocket == 0 {
			return fmt.Errorf("MCP endpoint is not a socket")
		}
		if conn, dialErr := net.DialTimeout("unix", s.Socket, 100*time.Millisecond); dialErr == nil {
			_ = conn.Close()
			return fmt.Errorf("MCP endpoint is already in use")
		} else if !errors.Is(dialErr, syscall.ECONNREFUSED) {
			return fmt.Errorf("MCP endpoint may be in use: %w", dialErr)
		}
		if err := os.Remove(s.Socket); err != nil {
			return fmt.Errorf("remove stale MCP endpoint: %w", err)
		}
	} else if !os.IsNotExist(err) {
		return err
	}
	l, err := net.Listen("unix", s.Socket)
	if err != nil {
		return err
	}
	defer l.Close()
	defer os.Remove(s.Socket)
	ctx := s.Context
	if ctx == nil {
		ctx = context.Background()
	}
	go func() {
		<-ctx.Done()
		_ = l.Close()
	}()
	if err := os.Chmod(s.Socket, 0600); err != nil {
		return err
	}
	if s.Ready != nil {
		s.Ready()
	}
	for {
		c, err := l.Accept()
		if err != nil {
			if ctx.Err() != nil {
				return ctx.Err()
			}
			return err
		}
		go handle(c, s.Handler)
	}
}
func handle(c net.Conn, handler Handler) {
	defer c.Close()
	scan := bufio.NewScanner(c)
	scan.Buffer(make([]byte, 4096), limits.MaxMCPLineBytes)
	enc := json.NewEncoder(c)
	for scan.Scan() {
		var r Request
		if err := json.Unmarshal(scan.Bytes(), &r); err != nil {
			if err := enc.Encode(Response{"2.0", nil, nil, &Error{Code: -32700, Message: "parse error"}}); err != nil {
				return
			}
			continue
		}
		write := func(response Response) bool { return enc.Encode(response) == nil }
		switch r.Method {
		case "initialize":
			if !write(Response{"2.0", r.ID, map[string]any{"name": "cifrarium", "version": "0.3.1"}, nil}) {
				return
			}
		case "status", "snapshot.plan", "restore.plan":
			if handler == nil {
				if !write(Response{"2.0", r.ID, nil, &Error{Code: -32603, Message: "daemon handler is unavailable"}}) {
					return
				}
				continue
			}
			result, err := handler.Handle(context.Background(), r)
			if err != nil {
				if !write(Response{"2.0", r.ID, nil, &Error{Code: -32000, Message: err.Error()}}) {
					return
				}
				continue
			}
			if !write(Response{"2.0", r.ID, result, nil}) {
				return
			}
		default:
			if !write(Response{"2.0", r.ID, nil, &Error{Code: -32601, Message: fmt.Sprintf("method %q is not available", r.Method)}}) {
				return
			}
		}
	}
	if err := scan.Err(); err != nil {
		_ = enc.Encode(Response{"2.0", nil, nil, &Error{Code: -32600, Message: "request rejected"}})
	}
}
