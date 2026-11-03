package clock

import (
	"testing"
	"time"
)

func TestClockSleepWaitsForMockTime(t *testing.T) {
	var testClock Clock
	testClock.Set(time.Unix(0, 0))
	defer testClock.Reset()

	registered := make(chan struct{})
	done := make(chan struct{})
	go func() {
		testClock.sleep(10*time.Second, func() {
			close(registered)
		})
		close(done)
	}()

	select {
	case <-registered:
	case <-time.After(time.Second):
		t.Fatal("Sleep did not register its mock timer")
	}

	if err := testClock.Add(9 * time.Second); err != nil {
		t.Fatal(err)
	}
	select {
	case <-done:
		t.Fatal("Sleep returned before its duration elapsed")
	default:
	}

	if err := testClock.Add(time.Second); err != nil {
		t.Fatal(err)
	}
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("Sleep did not return after its duration elapsed")
	}
}
