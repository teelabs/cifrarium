package daemon

import (
	"context"
	"errors"
	"fmt"
)

// Service performs a recovery of pending work and one immediate snapshot
// before entering the six-hour scheduler loop. Retryable upload failures are
// reported and retained in the encrypted queue; persistence failures are fatal.
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
	}
	return s.Scheduler.Run(ctx)
}
