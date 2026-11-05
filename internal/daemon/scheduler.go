package daemon

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"time"
)

const DefaultInterval = 6 * time.Hour

type Snapshotter func(context.Context) (Item, error)
type Uploader func(context.Context, Item) error
type RetryDecision uint8

const (
	StopRetry RetryDecision = iota
	RetryNow
)

type RetryHandler func(context.Context, error) RetryDecision

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
	Persist          func() error
	Report           func(error)
	RetryHandler     RetryHandler
}

type ReportedFailure struct{ Err error }

func (e *ReportedFailure) Error() string    { return e.Err.Error() }
func (e *ReportedFailure) Unwrap() error    { return e.Err }
func (e *ReportedFailure) ReportedFailure() {}

type PersistenceStage string

const (
	PersistenceStagePendingDrain PersistenceStage = "pending-drain"
	PersistenceStageSnapshot     PersistenceStage = "snapshot-upload"
	PersistenceStageRecovery     PersistenceStage = "recovery-snapshot"
)

type PersistenceError struct {
	Stage  PersistenceStage
	Err    error
	Upload error
}

func (e *PersistenceError) Error() string { return "pending queue state could not be persisted" }
func (e *PersistenceError) Unwrap() []error {
	if e.Upload != nil {
		return []error{e.Err, e.Upload}
	}
	return []error{e.Err}
}

type UploadStage string

const (
	UploadStagePendingDrain UploadStage = "pending-drain"
	UploadStageSnapshot     UploadStage = "snapshot-upload"
)

// UploadFailure marks an upload attempt failure without requiring the CLI to
// inspect or print underlying error text.
type UploadFailure struct {
	Stage UploadStage
	Err   error
}

func (e *UploadFailure) Error() string {
	if e.Stage == UploadStagePendingDrain {
		return "pending upload failed"
	}
	return "snapshot upload failed"
}
func (e *UploadFailure) Unwrap() error { return e.Err }

// QueueEnqueueFailure reports that a captured snapshot could not be retained
// for retry after its upload failed. It preserves both failures for typed
// inspection while keeping raw provider and filesystem messages out of Error.
type QueueEnqueueFailure struct {
	Upload  error
	Enqueue error
}

func (e *QueueEnqueueFailure) Error() string {
	if errors.Is(e.Enqueue, ErrQueueFull) {
		return "snapshot upload was not confirmed and pending queue is full"
	}
	return "snapshot upload was not confirmed and could not be added to pending queue"
}
func (e *QueueEnqueueFailure) Unwrap() []error { return []error{e.Upload, e.Enqueue} }

type RecoveryQueueFailure struct {
	Primary error
	Enqueue error
}

func (e *RecoveryQueueFailure) Error() string {
	if errors.Is(e.Enqueue, ErrQueueFull) {
		return "recovery snapshot could not be queued because pending queue is full"
	}
	return "recovery snapshot could not be added to pending queue"
}
func (e *RecoveryQueueFailure) Unwrap() []error { return []error{e.Primary, e.Enqueue} }

// CaptureError marks a failure while reading local configuration files. These
// failures are not retryable by the daemon because retrying would repeat the
// same local safety violation and could leave the operator without control of
// the foreground process.
type CaptureStage string

const (
	CaptureStageAdapters            CaptureStage = "adapters"
	CaptureStageVaultWrite          CaptureStage = "vault-write"
	CaptureStageSnapshotRead        CaptureStage = "snapshot-read"
	CaptureStageManifestPreparation CaptureStage = "manifest-preparation"
)

type CaptureError struct {
	Stage CaptureStage
	Err   error
}

func (e *CaptureError) Error() string   { return fmt.Sprintf("capture failed: %v", e.Err) }
func (e *CaptureError) Unwrap() error   { return e.Err }
func (e *CaptureError) CaptureFailure() {}

type RecoverySnapshotError struct {
	Primary  error
	Recovery error
}

func (e *RecoverySnapshotError) Error() string {
	return fmt.Sprintf("%v; recovery snapshot failed: %v", e.Primary, e.Recovery)
}

func (e *RecoverySnapshotError) Unwrap() []error {
	return []error{e.Primary, e.Recovery}
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
		uploadFailure := &UploadFailure{Stage: UploadStageSnapshot, Err: err}
		if qerr := s.Pending.Push(item); qerr != nil {
			return &QueueEnqueueFailure{Upload: uploadFailure, Enqueue: qerr}
		}
		if s.Persist != nil {
			if qerr := s.Persist(); qerr != nil {
				return &PersistenceError{Stage: PersistenceStageSnapshot, Err: qerr, Upload: uploadFailure}
			}
		}
		return s.missed(ctx, uploadFailure)
	}
	s.MissedCycles = 0
	return nil
}
func (s *Scheduler) DrainPending(ctx context.Context) error {
	for {
		item, ok := s.Pending.Peek()
		if !ok {
			return nil
		}
		if err := s.uploadWithRetry(ctx, item); err != nil {
			return &UploadFailure{Stage: UploadStagePendingDrain, Err: err}
		}
		_, _ = s.Pending.Pop()
		if s.Persist != nil {
			if err := s.Persist(); err != nil {
				_ = s.Pending.Prepend(item)
				return &PersistenceError{Stage: PersistenceStagePendingDrain, Err: err}
			}
		}
	}
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
				var persistenceErr *PersistenceError
				if errors.As(err, &persistenceErr) {
					return err
				}
				if s.Report != nil {
					s.Report(err)
				}
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
		recovery, recoveryErr := s.RecoverySnapshot(ctx)
		if recoveryErr != nil {
			return &RecoverySnapshotError{Primary: err, Recovery: recoveryErr}
		}
		if queueErr := s.Pending.Push(recovery); queueErr != nil {
			return &RecoveryQueueFailure{Primary: err, Enqueue: queueErr}
		}
		if s.Persist != nil {
			if persistErr := s.Persist(); persistErr != nil {
				return &PersistenceError{Stage: PersistenceStageRecovery, Err: persistErr, Upload: err}
			}
		}
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
