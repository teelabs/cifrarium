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
type Service struct{ Scheduler *Scheduler }

func (s Service) Run(ctx context.Context) error {
	if s.Scheduler == nil {
		return context.Canceled
	}
	if err := s.Scheduler.DrainPending(ctx); err != nil {
		return fmt.Errorf("initial pending drain failed: %w", err)
	}
	if err := s.Scheduler.Cycle(ctx); err != nil {
		var persistenceErr *PersistenceError
		if errors.As(err, &persistenceErr) {
			return fmt.Errorf("initial cycle persistence failed: %w", err)
		}
		if s.Scheduler.Report != nil {
			s.Scheduler.Report(err)
		}
		var captureErr interface{ CaptureFailure() }
		if errors.As(err, &captureErr) {
			return fmt.Errorf("initial capture failed: %w", err)
		}
	}
	return s.Scheduler.Run(ctx)
}
