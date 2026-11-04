// Package rpc provides the local, versioned control protocol used by Cifrarium
// clients. The wire format is JSON-RPC 2.0; the Linux transport is a private
// Unix socket and is intentionally hidden behind these package functions.
package rpc

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

const ProtocolVersion = "cifrarium.control.v1"

// Transport is the platform seam for local daemon IPC. The MVP provides only
// UnixTransport; future platform packages can add named-pipe implementations
// without changing the RPC contract or backend.
type Transport interface {
	Listen(endpoint string) (net.Listener, error)
	DialContext(context.Context, string) (net.Conn, error)
}

type UnixTransport struct{}

func (UnixTransport) Listen(endpoint string) (net.Listener, error) {
	return net.Listen("unix", endpoint)
}

func (UnixTransport) DialContext(ctx context.Context, endpoint string) (net.Conn, error) {
	return (&net.Dialer{}).DialContext(ctx, "unix", endpoint)
}

type Request struct {
	JSONRPC  string          `json:"jsonrpc"`
	ID       string          `json:"id"`
	Protocol string          `json:"protocol,omitempty"`
	Method   string          `json:"method"`
	Params   json.RawMessage `json:"params,omitempty"`
}

type Error struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
	Data    any    `json:"data,omitempty"`
}

func (e *Error) Error() string {
	if e == nil {
		return ""
	}
	return e.Message
}

type Response struct {
	JSONRPC  string          `json:"jsonrpc"`
	ID       string          `json:"id"`
	Protocol string          `json:"protocol,omitempty"`
	Result   json.RawMessage `json:"result,omitempty"`
	Error    *Error          `json:"error,omitempty"`
}

type Handler func(context.Context, Request) (any, *Error)

type Server struct {
	Socket   string
	Handler  Handler
	Ready    func()
	listener net.Listener
	cleanup  func() error
}

func ListenUnix(socket string, handler Handler, ready func()) (*Server, error) {
	if socket == "" {
		return nil, errors.New("RPC socket is required")
	}
	if err := os.MkdirAll(filepath.Dir(socket), 0700); err != nil {
		return nil, err
	}
	if info, err := os.Lstat(socket); err == nil {
		if info.Mode()&os.ModeSocket == 0 {
			return nil, fmt.Errorf("RPC endpoint is not a socket")
		}
		if conn, dialErr := net.DialTimeout("unix", socket, 100*time.Millisecond); dialErr == nil {
			_ = conn.Close()
			return nil, fmt.Errorf("RPC endpoint is already in use")
		} else if !errors.Is(dialErr, syscall.ECONNREFUSED) {
			return nil, fmt.Errorf("RPC endpoint may be in use: %w", dialErr)
		}
		if err := os.Remove(socket); err != nil {
			return nil, fmt.Errorf("remove stale RPC endpoint: %w", err)
		}
	} else if !os.IsNotExist(err) {
		return nil, err
	}
	listener, err := (UnixTransport{}).Listen(socket)
	if err != nil {
		return nil, err
	}
	if err := os.Chmod(socket, 0600); err != nil {
		_ = listener.Close()
		_ = os.Remove(socket)
		return nil, err
	}
	server := NewServer(socket, listener, handler, ready, func() error { return os.Remove(socket) })
	if ready != nil {
		ready()
	}
	return server, nil
}

// NewServer binds an already-created platform listener to the RPC protocol.
// Platform-specific transport packages can use this constructor in the future.
func NewServer(endpoint string, listener net.Listener, handler Handler, ready func(), cleanup func() error) *Server {
	return &Server{Socket: endpoint, Handler: handler, Ready: ready, listener: listener, cleanup: cleanup}
}

func (s *Server) Serve(ctx context.Context) error {
	if s == nil || s.listener == nil {
		return errors.New("RPC server is not listening")
	}
	go func() {
		<-ctx.Done()
		_ = s.listener.Close()
	}()
	for {
		conn, err := s.listener.Accept()
		if err != nil {
			if ctx.Err() != nil {
				return ctx.Err()
			}
			return err
		}
		go serveConn(ctx, conn, s.Handler)
	}
}

func (s *Server) Close() error {
	if s == nil || s.listener == nil {
		return nil
	}
	err := s.listener.Close()
	if s.cleanup != nil {
		_ = s.cleanup()
	}
	return err
}

func serveConn(ctx context.Context, conn net.Conn, handler Handler) {
	defer conn.Close()
	scanner := bufio.NewScanner(conn)
	scanner.Buffer(make([]byte, 4096), limits.MaxMCPLineBytes)
	encoder := json.NewEncoder(conn)
	for scanner.Scan() {
		var request Request
		if err := json.Unmarshal(scanner.Bytes(), &request); err != nil {
			_ = encoder.Encode(Response{JSONRPC: "2.0", Protocol: ProtocolVersion, Error: &Error{Code: -32700, Message: "parse error"}})
			continue
		}
		response := Response{JSONRPC: "2.0", ID: request.ID, Protocol: ProtocolVersion}
		if request.JSONRPC != "2.0" || request.ID == "" || request.Method == "" {
			response.Error = &Error{Code: -32600, Message: "invalid request"}
		} else if request.Protocol != "" && request.Protocol != ProtocolVersion {
			response.Error = &Error{Code: -32002, Message: "unsupported RPC protocol version"}
		} else if handler == nil {
			response.Error = &Error{Code: -32603, Message: "RPC handler unavailable"}
		} else {
			result, rpcErr := handler(ctx, request)
			if rpcErr != nil {
				response.Error = rpcErr
			} else if result != nil {
				encoded, err := json.Marshal(result)
				if err != nil {
					response.Error = &Error{Code: -32603, Message: "could not encode RPC result"}
				} else {
					response.Result = encoded
				}
			}
		}
		if err := encoder.Encode(response); err != nil {
			return
		}
	}
	if err := scanner.Err(); err != nil {
		_ = encoder.Encode(Response{JSONRPC: "2.0", Protocol: ProtocolVersion, Error: &Error{Code: -32004, Message: "request too large or rejected"}})
	}
}

func Call(ctx context.Context, socket, method string, params any, result any) error {
	return CallWithTransport(UnixTransport{}, ctx, socket, method, params, result)
}

func CallWithTransport(transport Transport, ctx context.Context, socket, method string, params any, result any) error {
	if transport == nil {
		return errors.New("RPC transport is required")
	}
	if socket == "" || method == "" {
		return errors.New("RPC socket and method are required")
	}
	conn, err := transport.DialContext(ctx, socket)
	if err != nil {
		return err
	}
	defer conn.Close()
	connectionDone := make(chan struct{})
	defer close(connectionDone)
	go func() {
		select {
		case <-ctx.Done():
			_ = conn.Close()
		case <-connectionDone:
		}
	}()
	if deadline, ok := ctx.Deadline(); ok {
		_ = conn.SetDeadline(deadline)
	}
	body, err := json.Marshal(params)
	if err != nil {
		return fmt.Errorf("encode RPC parameters: %w", err)
	}
	request := Request{JSONRPC: "2.0", ID: fmt.Sprintf("%d", time.Now().UnixNano()), Protocol: ProtocolVersion, Method: method, Params: body}
	if err := json.NewEncoder(conn).Encode(request); err != nil {
		return err
	}
	var response Response
	if err := json.NewDecoder(bufio.NewReader(conn)).Decode(&response); err != nil {
		return err
	}
	if response.JSONRPC != "2.0" || (response.Protocol != "" && response.Protocol != ProtocolVersion) {
		return errors.New("unsupported RPC protocol response")
	}
	if response.Error != nil {
		return response.Error
	}
	if result == nil || len(response.Result) == 0 {
		return nil
	}
	if err := json.Unmarshal(response.Result, result); err != nil {
		return fmt.Errorf("decode RPC result: %w", err)
	}
	return nil
}
