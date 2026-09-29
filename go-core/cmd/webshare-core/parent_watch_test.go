package main

import (
	"context"
	"sync/atomic"
	"testing"
	"time"
)

// ISSUE-003: the parent-watch loop must trigger shutdown once the
// launcher PID disappears (any platform), and must stay quiet while the
// parent is alive.
func TestWatchParentStopsWhenParentGone(t *testing.T) {
	old := parentPollInterval
	parentPollInterval = 10 * time.Millisecond
	defer func() { parentPollInterval = old }()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	var stopped atomic.Int32
	stop := func() {
		stopped.Add(1)
		cancel()
	}
	var calls atomic.Int32
	done := make(chan struct{})
	go func() {
		defer close(done)
		watchParentWithAlive(ctx, 12345, stop, func(pid int) bool {
			if pid != 12345 {
				t.Errorf("probe pid = %d, want 12345", pid)
			}
			// Alive twice, then gone.
			return calls.Add(1) < 3
		})
	}()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("watchParent did not return after parent died")
	}
	if got := stopped.Load(); got != 1 {
		t.Fatalf("stop called %d times, want 1", got)
	}
}

func TestWatchParentReturnsOnContextCancel(t *testing.T) {
	old := parentPollInterval
	parentPollInterval = 10 * time.Millisecond
	defer func() { parentPollInterval = old }()

	ctx, cancel := context.WithCancel(context.Background())
	var stopped atomic.Int32
	done := make(chan struct{})
	go func() {
		defer close(done)
		watchParentWithAlive(ctx, 99999, func() {
			stopped.Add(1)
		}, func(int) bool { return true })
	}()
	cancel()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("watchParent did not return on context cancel")
	}
	if got := stopped.Load(); got != 0 {
		t.Fatalf("stop called %d times while parent alive", got)
	}
}
