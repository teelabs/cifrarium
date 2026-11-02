package daemon

import (
	"context"
	"errors"
	"testing"
	"time"
)

func TestSchedulerRetriesAndResetsMissedCycle(t *testing.T) {
	q := Queue{}
	attempts := 0
	s := NewScheduler(func(context.Context) (Item, error) { return Item{ID: "s", Ciphertext: []byte("c")}, nil }, func(context.Context, Item) error {
		attempts++
		if attempts < 3 {
			return errors.New("offline")
		}
		return nil
	}, &q)
	s.Retry.BaseDelay = 0
	s.Retry.Sleep = func(context.Context, time.Duration) error { return nil }
	if err := s.Cycle(context.Background()); err != nil {
		t.Fatal(err)
	}
	if attempts != 3 || s.MissedCycles != 0 || q.Len() != 0 {
		t.Fatalf("attempts=%d missed=%d queue=%d", attempts, s.MissedCycles, q.Len())
	}
}
func TestSchedulerQueuesAndCreatesRecoveryAfterFailure(t *testing.T) {
	q := Queue{}
	recovery := 0
	s := NewScheduler(func(context.Context) (Item, error) { return Item{ID: "s", Ciphertext: []byte("c")}, nil }, func(context.Context, Item) error { return errors.New("offline") }, &q)
	s.Retry.MaxAttempts = 2
	s.Retry.BaseDelay = 0
	s.Retry.Sleep = func(context.Context, time.Duration) error { return nil }
	s.RecoverySnapshot = func(context.Context) (Item, error) {
		recovery++
		return Item{ID: "recovery", Ciphertext: []byte("c")}, nil
	}
	if err := s.Cycle(context.Background()); err == nil {
		t.Fatal("offline cycle succeeded")
	}
	if q.Len() != 2 || recovery != 1 || s.MissedCycles != 1 {
		t.Fatalf("queue=%d recovery=%d missed=%d", q.Len(), recovery, s.MissedCycles)
	}
	if first, ok := q.Pop(); !ok || first.ID != "s" {
		t.Fatalf("first queued item=%q", first.ID)
	}
	if second, ok := q.Pop(); !ok || second.ID != "recovery" {
		t.Fatalf("recovery queued item=%q", second.ID)
	}
	_ = s.Cycle(context.Background())
	if recovery != 1 {
		t.Fatal("recovery snapshot not deduplicated")
	}
}
func TestIncidentDeduper(t *testing.T) {
	d := IncidentDeduper{}
	if !d.First("network") {
		t.Fatal("first incident suppressed")
	}
	if d.First("network") {
		t.Fatal("duplicate incident notified")
	}
	if !d.First("keyring") {
		t.Fatal("distinct incident suppressed")
	}
	for i := 0; i < MaxIncidentKeys+10; i++ {
		d.First("incident-" + string(rune(i)))
	}
	if len(d.seen) > MaxIncidentKeys {
		t.Fatalf("deduper grew beyond bound: %d", len(d.seen))
	}
}
