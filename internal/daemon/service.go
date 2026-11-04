package daemon

import (
	"context"
	"errors"
	"fmt"
)

// Service performs a recovery of pending work and one immediate snapshot
// before entering the six-hour scheduler loop. Local capture failures are
// reported and returned so a foreground daemon exits; retryable upload
// failures are reported and retained in the encrypted queue.
type Service struct {
	Scheduler *Scheduler
	Ready     func()
}

func (s Service) Run(ctx context.Context) error {
	if s.Scheduler == nil {
		return context.Canceled
	}
	for {
		if err := s.Scheduler.DrainPending(ctx); err != nil {
			initialErr := fmt.Errorf("initial pending drain failed: %w", err)
			var persistenceErr *PersistenceError
			if errors.As(err, &persistenceErr) || ctx.Err() != nil {
				return initialErr
			}
			if s.Scheduler.RetryHandler != nil && s.Scheduler.RetryHandler(ctx, err) == RetryNow {
				continue
			}
			if s.Scheduler.RetryHandler != nil {
				return &ReportedFailure{Err: initialErr}
			}
			return initialErr
		}
		if err := s.Scheduler.Cycle(ctx); err != nil {
			var persistenceErr *PersistenceError
			if errors.As(err, &persistenceErr) {
				return fmt.Errorf("initial cycle persistence failed: %w", err)
			}
			if ctx.Err() != nil {
				return err
			}
			var captureErr interface{ CaptureFailure() }
			if errors.As(err, &captureErr) {
				if s.Scheduler.Report != nil {
					s.Scheduler.Report(err)
				}
				return fmt.Errorf("initial capture failed: %w", err)
			}
			if s.Scheduler.RetryHandler != nil {
				if s.Scheduler.RetryHandler(ctx, err) == RetryNow {
					continue
				}
				return &ReportedFailure{Err: fmt.Errorf("initial cycle failed: %w", err)}
			}
			if s.Scheduler.Report != nil {
				s.Scheduler.Report(err)
			}
		}
		break
	}
	if s.Ready != nil {
		s.Ready()
	}
	return s.Scheduler.Run(ctx)
}
