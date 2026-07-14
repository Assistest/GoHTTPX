package main

import "testing"

func TestControlWriteTimeoutDoesNotCapTargetRequestDuration(t *testing.T) {
	if controlWriteTimeout != 0 {
		t.Fatalf("control WriteTimeout=%s; valid target requests may run for up to 10m", controlWriteTimeout)
	}
}
