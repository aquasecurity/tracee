// package queue defines the interface and and implementation of a queue for events storage.
// the interface is defined by EventQueue while the (currently only) implementation is defined by
// eventQueueMem.
package queue

import (
	"github.com/aquasecurity/tracee/types/trace"
)

type CacheConfig EventQueue

type EventQueue interface {
	String() string
	Enqueue(*trace.Event)
	Dequeue() *trace.Event
}
