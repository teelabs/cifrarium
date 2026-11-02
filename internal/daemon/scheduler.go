package daemon

import (
	"context"
	"fmt"
	"sync"
	"time"
)

const DefaultInterval = 6 * time.Hour

type Snapshotter func(context.Context) (Item, error)
type Uploader func(context.Context, Item) error
type RetryPolicy struct {
	MaxAttempts int
	BaseDelay   time.Duration
	Sleep       func(context.Context, time.Duration) error
}
type Scheduler struct {
	Interval         time.Duration
	Retry            RetryPolicy
	Snapshot         Snapshotter
	Upload           Uploader
	RecoverySnapshot Snapshotter
	Pending          *Queue
	MissedCycles     int
}

func NewScheduler(snapshot Snapshotter, upload Uploader, pending *Queue) *Scheduler {
	return &Scheduler{Interval: DefaultInterval, Retry: RetryPolicy{MaxAttempts: 3, BaseDelay: time.Second}, Snapshot: snapshot, Upload: upload, Pending: pending}
}
func (s *Scheduler) Cycle(ctx context.Context) error {
	if s.Snapshot == nil || s.Upload == nil || s.Pending == nil {
		return fmt.Errorf("scheduler is not configured")
	}
	item, err := s.Snapshot(ctx)
	if err != nil {
		return s.missed(ctx, err)
	}
	if err := s.uploadWithRetry(ctx, item); err != nil {
		if qerr := s.Pending.Push(item); qerr != nil {
			return fmt.Errorf("upload failed: %v; queue failed: %w", err, qerr)
		}
		return s.missed(ctx, err)
	}
	s.MissedCycles = 0
	return nil
}
func (s *Scheduler) DrainPending(ctx context.Context) error {
	for s.Pending.Len() > 0 {
		item, _ := s.Pending.Pop()
		if err := s.uploadWithRetry(ctx, item); err != nil {
			_ = s.Pending.Push(item)
			return err
		}
	}
	return nil
}
func (s *Scheduler) Run(ctx context.Context) error {
	if s.Interval <= 0 {
		s.Interval = DefaultInterval
	}
	ticker := time.NewTicker(s.Interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-ticker.C:
			if err := s.Cycle(ctx); err != nil {
				continue
			}
		}
	}
}
func (s *Scheduler) uploadWithRetry(ctx context.Context, item Item) error {
	attempts := s.Retry.MaxAttempts
	if attempts < 1 {
		attempts = 1
	}
	for attempt := 1; attempt <= attempts; attempt++ {
		if err := s.Upload(ctx, item); err == nil {
			return nil
		} else if attempt == attempts {
			return err
		}
		delay := s.Retry.BaseDelay * time.Duration(1<<(attempt-1))
		if s.Retry.Sleep != nil {
			if err := s.Retry.Sleep(ctx, delay); err != nil {
				return err
			}
		} else {
			timer := time.NewTimer(delay)
			select {
			case <-ctx.Done():
				timer.Stop()
				return ctx.Err()
			case <-timer.C:
			}
		}
	}
	return nil
}
func (s *Scheduler) missed(ctx context.Context, err error) error {
	s.MissedCycles++
	if s.MissedCycles == 1 && s.RecoverySnapshot != nil {
		_, _ = s.RecoverySnapshot(ctx)
	}
	return err
}

type IncidentDeduper struct {
	mu    sync.Mutex
	seen  map[string]struct{}
	order []string
}

const MaxIncidentKeys = 128

func (d *IncidentDeduper) First(id string) bool {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.seen == nil {
		d.seen = map[string]struct{}{}
	}
	if _, ok := d.seen[id]; ok {
		return false
	}
	if len(d.order) >= MaxIncidentKeys {
		delete(d.seen, d.order[0])
		d.order = d.order[1:]
	}
	d.seen[id] = struct{}{}
	d.order = append(d.order, id)
	return true
}
