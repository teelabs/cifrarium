package daemon

import (
	"context"
	"testing"
	"time"
)

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

func TestDrainPendingRestoresItemWhenPersistenceFails(t *testing.T) {
	q := Queue{}
	if err := q.Push(Item{ID: "pending", Ciphertext: []byte("c")}); err != nil {
		t.Fatal(err)
	}
	s := NewScheduler(nil, nil, &q)
	s.Persist = func() error { return context.Canceled }
	if err := s.DrainPending(context.Background()); err == nil {
		t.Fatal("persistence failure ignored")
	}
	if q.Len() != 1 {
		t.Fatalf("pending item lost: %d", q.Len())
	}
}
