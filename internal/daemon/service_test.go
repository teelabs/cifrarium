package daemon

import (
	"context"
	"errors"
	"path/filepath"
	"testing"
	"time"
)

type testCaptureError struct{ err error }

func (e *testCaptureError) Error() string   { return e.err.Error() }
func (e *testCaptureError) Unwrap() error   { return e.err }
func (e *testCaptureError) CaptureFailure() {}

func TestServiceStopsAfterInitialCaptureFailure(t *testing.T) {
	q := Queue{}
	reported := 0
	s := NewScheduler(func(context.Context) (Item, error) {
		return Item{}, &testCaptureError{err: errors.New("symlink rejected: .zshrc")}
	}, func(context.Context, Item) error { return nil }, &q)
	s.Report = func(error) { reported++ }
	s.Interval = time.Hour

	ctx, cancel := context.WithTimeout(context.Background(), 25*time.Millisecond)
	defer cancel()
	err := (Service{Scheduler: s}).Run(ctx)

	var captureErr interface{ CaptureFailure() }
	if !errors.As(err, &captureErr) {
		t.Fatalf("initial capture error = %v, want capture failure", err)
	}
	if reported != 1 {
		t.Fatalf("reported=%d, want 1", reported)
	}
}

func TestServiceKeepsRetryingAfterInitialUploadFailure(t *testing.T) {
	q := Queue{}
	reported := 0
	s := NewScheduler(func(context.Context) (Item, error) {
		return Item{ID: "snapshot", Ciphertext: []byte("cipher")}, nil
	}, func(context.Context, Item) error { return errors.New("provider offline") }, &q)
	s.Retry.MaxAttempts = 1
	s.Interval = time.Millisecond
	s.Report = func(error) { reported++ }

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Millisecond)
	defer cancel()
	err := (Service{Scheduler: s}).Run(ctx)

	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("service error=%v, want context deadline after retry loop", err)
	}
	if reported == 0 {
		t.Fatal("initial upload failure was not reported while scheduler continued")
	}
}

func TestServiceRunsInitialCycle(t *testing.T) {
	q := Queue{}
	calls := 0
	s := NewScheduler(func(context.Context) (Item, error) { calls++; return Item{ID: "x", Ciphertext: []byte("x")}, nil }, func(context.Context, Item) error { return nil }, &q)
	s.Interval = time.Millisecond
	ctx, cancel := context.WithCancel(context.Background())
	go func() { time.Sleep(5 * time.Millisecond); cancel() }()
	_ = (Service{Scheduler: s}).Run(ctx)
	if calls == 0 {
		t.Fatal("initial cycle not run")
	}
}

func TestDrainPendingKeepsItemWhenUploadFails(t *testing.T) {
	q := Queue{}
	if err := q.Push(Item{ID: "pending", Ciphertext: []byte("c")}); err != nil {
		t.Fatal(err)
	}
	s := NewScheduler(nil, func(context.Context, Item) error { return context.Canceled }, &q)
	s.Retry.MaxAttempts = 1
	if err := s.DrainPending(context.Background()); err == nil {
		t.Fatal("upload failure ignored")
	}
	if q.Len() != 1 {
		t.Fatalf("pending item lost: %d", q.Len())
	}
}

func TestServiceReturnsInitialDrainFailure(t *testing.T) {
	q := Queue{}
	if err := q.Push(Item{ID: "pending", Ciphertext: []byte("c")}); err != nil {
		t.Fatal(err)
	}
	s := NewScheduler(func(context.Context) (Item, error) { return Item{ID: "new", Ciphertext: []byte("c")}, nil }, func(context.Context, Item) error { return context.Canceled }, &q)
	s.Retry.MaxAttempts = 1
	if err := (Service{Scheduler: s}).Run(context.Background()); err == nil {
		t.Fatal("initial drain failure was swallowed")
	}
}

func TestServiceReturnsInitialCyclePersistenceFailure(t *testing.T) {
	q := Queue{}
	s := NewScheduler(func(context.Context) (Item, error) { return Item{ID: "new", Ciphertext: []byte("c")}, nil }, func(context.Context, Item) error { return context.Canceled }, &q)
	s.Retry.MaxAttempts = 1
	s.Persist = func() error { return context.DeadlineExceeded }
	if err := (Service{Scheduler: s}).Run(context.Background()); err == nil {
		t.Fatal("initial cycle persistence failure was swallowed")
	}
	if q.Len() != 1 {
		t.Fatalf("queued item lost: %d", q.Len())
	}
}

func TestDrainPendingReturnsRequeuePersistenceFailure(t *testing.T) {
	key := make([]byte, 32)
	path := filepath.Join(t.TempDir(), "queue")
	q := Queue{}
	if err := q.Push(Item{ID: "pending", Ciphertext: []byte("c")}); err != nil {
		t.Fatal(err)
	}
	if err := q.Save(path, key); err != nil {
		t.Fatal(err)
	}
	loaded, err := Load(path, key)
	if err != nil {
		t.Fatal(err)
	}
	s := NewScheduler(nil, func(context.Context, Item) error { return nil }, loaded)
	s.Retry.MaxAttempts = 1
	s.Persist = func() error { return context.DeadlineExceeded }
	if err := s.DrainPending(context.Background()); err == nil {
		t.Fatal("removal persistence failure ignored")
	}
	if loaded.Len() != 1 {
		t.Fatalf("pending item lost in memory after persistence failure: %d", loaded.Len())
	}
	reloaded, err := Load(path, key)
	if err != nil {
		t.Fatal(err)
	}
	if reloaded.Len() != 1 {
		t.Fatalf("pending item lost durably after persistence failure: %d", reloaded.Len())
	}
}
