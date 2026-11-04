package main

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"math"
	"os"
	"strings"
	"time"

	"github.com/teelabs/cifrarium/internal/daemon"
	"golang.org/x/sys/unix"
)

const defaultDaemonRetryTimeout = 30 * time.Second

type daemonRetryController struct {
	home        string
	interactive bool
	tty         *os.File
	reader      *bufio.Reader
	output      io.Writer
	timeout     time.Duration
	wait        func(context.Context, *daemonRetryController) error
}

func newDaemonRetryController(home string, output io.Writer) *daemonRetryController {
	controller := &daemonRetryController{
		home:    home,
		output:  output,
		timeout: daemonRetryTimeout(),
		wait:    waitForDaemonRetry,
	}
	if !writerIsTerminal(output) {
		return controller
	}
	tty, err := openSetupTTY()
	if err != nil {
		return controller
	}
	controller.interactive = true
	controller.tty = tty
	controller.reader = bufio.NewReader(tty)
	return controller
}

func (c *daemonRetryController) Close() error {
	if c.tty == nil {
		return nil
	}
	return c.tty.Close()
}

func daemonRetryTimeout() time.Duration {
	value := strings.TrimSpace(os.Getenv("CIFRARIUM_DAEMON_RETRY_TIMEOUT"))
	if value == "" {
		return defaultDaemonRetryTimeout
	}
	timeout, err := time.ParseDuration(value)
	if err != nil || timeout <= 0 {
		return defaultDaemonRetryTimeout
	}
	return timeout
}

func (c *daemonRetryController) Handle(ctx context.Context, err error) daemon.RetryDecision {
	if ctx.Err() != nil {
		return daemon.StopRetry
	}
	if c.interactive {
		if c.reader == nil {
			return daemon.StopRetry
		}
		retry, promptErr := promptYesNo(c.reader, c.output, "Retry?", true)
		if promptErr != nil || !retry {
			return daemon.StopRetry
		}
	}
	renderDaemonFailure(c.output, c.home, err)
	if c.interactive {
		fmt.Fprintln(c.output, "The daemon is waiting for your action in another console.")
		fmt.Fprintln(c.output, "Press Enter at any time to retry immediately.")
	} else {
		fmt.Fprintln(c.output, "The daemon is waiting for corrective action in another console.")
	}
	if c.wait == nil {
		return daemon.RetryNow
	}
	if waitErr := c.wait(ctx, c); waitErr != nil {
		return daemon.StopRetry
	}
	return daemon.RetryNow
}

func waitForDaemonRetry(ctx context.Context, c *daemonRetryController) error {
	if c.tty == nil {
		displayTimeout := c.timeout.Round(time.Second)
		if displayTimeout <= 0 {
			displayTimeout = time.Second
		}
		fmt.Fprintf(c.output, "Next retry in %s; waiting for corrective action in another console.\n", displayTimeout)
		timer := time.NewTimer(c.timeout)
		select {
		case <-ctx.Done():
			if !timer.Stop() {
				<-timer.C
			}
			return ctx.Err()
		case <-timer.C:
			fmt.Fprintln(c.output, "Retrying now.")
			return nil
		}
	}
	deadline := time.Now().Add(c.timeout)
	for {
		remaining := time.Until(deadline)
		if remaining <= 0 {
			if c.interactive {
				fmt.Fprint(c.output, "\r\033[2KRetrying now...\n")
			}
			return nil
		}
		seconds := int(math.Ceil(remaining.Seconds()))
		if c.interactive {
			fmt.Fprintf(c.output, "\r\033[2KRetrying in %ds (press Enter to continue)", seconds)
		} else {
			fmt.Fprintf(c.output, "Retrying in %ds; waiting for corrective action in another console.\n", seconds)
		}

		pollDuration := remaining
		if pollDuration > time.Second {
			pollDuration = time.Second
		}
		fds := []unix.PollFd{{Fd: int32(c.tty.Fd()), Events: unix.POLLIN}}
		ready, err := unix.Poll(fds, int(pollDuration/time.Millisecond))
		if err != nil {
			if err == unix.EINTR {
				continue
			}
			return err
		}
		if ready > 0 && fds[0].Revents&unix.POLLIN != 0 {
			_, err := c.reader.ReadString('\n')
			if err != nil && err != io.EOF {
				return err
			}
			fmt.Fprint(c.output, "\r\033[2KRetrying now...\n")
			return nil
		}
		if ctx.Err() != nil {
			return ctx.Err()
		}
	}
}
