package daemon

import "context"

// Service performs a recovery of pending work and one immediate snapshot
// before entering the six-hour scheduler loop. Errors are retained in the
// encrypted queue; the daemon stays alive for the next cycle.
type Service struct{ Scheduler *Scheduler }

func (s Service) Run(ctx context.Context) error {
	if s.Scheduler == nil {
		return context.Canceled
	}
	_ = s.Scheduler.DrainPending(ctx)
	_ = s.Scheduler.Cycle(ctx)
	return s.Scheduler.Run(ctx)
}
