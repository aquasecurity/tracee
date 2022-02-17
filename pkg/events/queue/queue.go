package queue

import (
	"github.com/aquasecurity/tracee/types/trace"
)

type CacheConfig EventQueue

type EventQueue interface {
	String() string
	Setup() error
	Enqueue(*trace.Event)
	Dequeue() *trace.Event // bool is for blocking (true) or non-blocking (false)
}
