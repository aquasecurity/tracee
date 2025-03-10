package heartbeat

import (
	"context"
	"sync"
	"time"
)

var instance *Heartbeat
var once sync.Once
var closeOncePulse sync.Once

// Heartbeat represents the liveness detection logic, tracking pulse intervals
// and determining whether the system is healthy based on activity.
type Heartbeat struct {
	ctx       context.Context
	pulse     chan struct{}
	mu        sync.RWMutex
	isHealthy bool
	interval  time.Duration
	timeout   time.Duration
	callback  func()
}

// Init initializes the singleton Heartbeat instance and starts the internal monitor.
// It ensures that the heartbeat is only initialized once with the provided context,
// heartbeat interval, and timeout duration.
func Init(ctx context.Context, interval, timeout time.Duration) {
	once.Do(func() {
		instance = &Heartbeat{
			pulse:     make(chan struct{}, 1),
			mu:        sync.RWMutex{},
			isHealthy: false,
			ctx:       ctx,
			interval:  interval,
			timeout:   timeout,
		}
		instance.monitor()
	})
}

// GetInstance returns the singleton instance of Heartbeat.
func GetInstance() *Heartbeat {
	return instance
}

// SetCallback assigns a custom callback function to be executed on each heartbeat tick.
func (h *Heartbeat) SetCallback(cb func()) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.callback = cb
}

// Start begins the heartbeat pulse loop, which triggers the callback function
// at the configured interval until the context is cancelled.
func (h *Heartbeat) Start() {
	go func() {
		ticker := time.NewTicker(h.interval)
		defer ticker.Stop()

		for {
			select {
			case <-ticker.C:
				h.mu.RLock()
				cb := h.callback
				h.mu.RUnlock()
				if cb != nil {
					cb()
				}
			case <-h.ctx.Done():
				h.close()
				return
			}
		}
	}()
}

// SendPulse provides a public way to manually send a heartbeat signal.
func SendPulse() {
	select {
	case GetInstance().pulse <- struct{}{}:
	default:
		// Channel was full; drop the pulse instead of blocking
	}
}

// monitor periodically checks if heartbeats are received within the allowed timeout window.
// If no pulse is received in time, the health status is set to false.
func (h *Heartbeat) monitor() {
	go func() {
		timer := time.NewTimer(h.timeout)
		defer timer.Stop()

		for {
			select {
			case <-h.ctx.Done():
				h.close()
				return
			case <-h.pulse:
				h.setHealth(true)
				if !timer.Stop() {
					<-timer.C
				}
				timer.Reset(h.timeout)
			case <-timer.C:
				h.setHealth(false)
				timer.Reset(h.timeout)
			}
		}
	}()
}

// setHealth safely updates the internal health status.
func (h *Heartbeat) setHealth(status bool) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.isHealthy = status
}

// IsAlive returns the current health status of the Heartbeat instance.
func (h *Heartbeat) IsAlive() bool {
	h.mu.RLock()
	defer h.mu.RUnlock()
	return h.isHealthy
}

// close safely closes the heartbeat pulse channel.
//
// It ensures that the channel is closed only once using sync.Once to prevent
// panics due to multiple close attempts. This method should be called during
// shutdown or cleanup to signal that no more heartbeat pulses will be sent.
func (h *Heartbeat) close() {
	closeOncePulse.Do(func() {
		close(h.pulse)
	})
}
