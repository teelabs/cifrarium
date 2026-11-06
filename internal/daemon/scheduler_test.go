package daemon

import (
	"context"
	"errors"
	"fmt"
	"strings"
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

func TestSchedulerDoesNotDuplicateUnchangedHeadAfterRepeatedUploadFailure(t *testing.T) {
	q := &Queue{}
	item := Item{ID: "current-head", Ciphertext: []byte("ciphertext"), Manifest: []byte("manifest"), Unchanged: true}
	s := NewScheduler(func(context.Context) (Item, error) { return item, nil }, func(context.Context, Item) error {
		return errors.New("offline")
	}, q)
	s.Retry.MaxAttempts = 1
	for range 3 {
		if err := s.Cycle(context.Background()); err == nil {
			t.Fatal("offline cycle succeeded")
		}
	}
	if q.Len() != 1 {
		t.Fatalf("repeated unchanged upload failure queued %d copies, want 1", q.Len())
	}
	queued, ok := q.Peek()
	if !ok || queued.ID != item.ID || string(queued.Ciphertext) != string(item.Ciphertext) || string(queued.Manifest) != string(item.Manifest) {
		t.Fatalf("queued item = %#v, want exact current head", queued)
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

func TestSchedulerPreservesRecoveryCaptureFailureType(t *testing.T) {
	q := Queue{}
	recoveryFailure := &CaptureError{Stage: CaptureStageAdapters, Err: errors.New("adapter collection failed")}
	s := NewScheduler(
		func(context.Context) (Item, error) { return Item{ID: "s", Ciphertext: []byte("cipher")}, nil },
		func(context.Context, Item) error { return errors.New("provider offline") },
		&q,
	)
	s.Retry.MaxAttempts = 1
	s.RecoverySnapshot = func(context.Context) (Item, error) { return Item{}, recoveryFailure }
	err := s.Cycle(context.Background())
	var recoverySnapshotErr *RecoverySnapshotError
	if !errors.As(err, &recoverySnapshotErr) || recoverySnapshotErr.Primary == nil || recoverySnapshotErr.Recovery == nil {
		t.Fatalf("cycle error did not preserve both recovery failure causes: %#v", recoverySnapshotErr)
	}
	var captureErr *CaptureError
	if !errors.As(err, &captureErr) || captureErr.Stage != CaptureStageAdapters {
		t.Fatalf("combined cycle error lost typed recovery failure: %#v (%v)", captureErr, err)
	}
}

func TestSchedulerPreservesRecoveryQueueFailureType(t *testing.T) {
	q := Queue{}
	for i := 0; i < MaxPending; i++ {
		if err := q.Push(Item{ID: fmt.Sprintf("queued-%d", i), Ciphertext: []byte("cipher")}); err != nil {
			t.Fatal(err)
		}
	}
	s := NewScheduler(nil, nil, &q)
	s.RecoverySnapshot = func(context.Context) (Item, error) {
		return Item{ID: "recovery", Ciphertext: []byte("cipher")}, nil
	}
	err := s.missed(context.Background(), errors.New("private primary cause"))
	var recoveryQueueFailure *RecoveryQueueFailure
	if !errors.As(err, &recoveryQueueFailure) {
		t.Fatalf("missed error = %T, want RecoveryQueueFailure: %v", err, err)
	}
	if !errors.Is(err, ErrQueueFull) {
		t.Fatalf("missed error = %v, want ErrQueueFull", err)
	}
	if strings.Contains(err.Error(), "private primary cause") {
		t.Fatalf("recovery queue failure exposed primary error: %v", err)
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

func TestSchedulerReportsRetryableCycleFailure(t *testing.T) {
	q := Queue{}
	reported := make(chan error, 1)
	s := NewScheduler(func(context.Context) (Item, error) { return Item{}, errors.New("capture failed") }, func(context.Context, Item) error { return nil }, &q)
	s.Interval = time.Millisecond
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	s.Report = func(err error) {
		select {
		case reported <- err:
		default:
		}
		cancel()
	}
	_ = s.Run(ctx)
	select {
	case err := <-reported:
		if err == nil || err.Error() != "capture failed" {
			t.Fatalf("reported=%v", err)
		}
	default:
		t.Fatal("cycle failure was not reported")
	}
}

func TestSchedulerStopsOnScheduledPersistenceFailure(t *testing.T) {
	q := Queue{}
	s := NewScheduler(func(context.Context) (Item, error) {
		return Item{ID: "snapshot", Ciphertext: []byte("cipher")}, nil
	}, func(context.Context, Item) error {
		return errors.New("offline")
	}, &q)
	s.Interval = time.Millisecond
	s.Retry.MaxAttempts = 1
	s.Persist = func() error { return errors.New("disk full") }
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if err := s.Run(ctx); err == nil {
		t.Fatal("scheduled persistence failure was swallowed")
	}
}
