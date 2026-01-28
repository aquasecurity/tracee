package server

// InvokeHeartbeat is a no-op function used as a callback for heartbeat.
// It's instrumented by an uprobe to detect liveness.
// This function is shared between HTTP and gRPC servers.
//
//go:noinline
func InvokeHeartbeat() {
	// Intentionally left empty
}
