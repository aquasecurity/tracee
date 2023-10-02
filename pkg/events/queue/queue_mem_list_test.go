package queue

import (
	"sync"
	"testing"

	"gotest.tools/assert"

	"github.com/aquasecurity/tracee/types/trace"
)

func TestEnqueueDequeue(t *testing.T) {
	t.Parallel()

	q := NewEventQueueMem(1024)
	wg := sync.WaitGroup{}
	wg.Add(1)
	go func() {
		i := 0
		for {
			e := q.Dequeue()
			assert.Equal(t, i, e.Timestamp)
			i++
			if i == 999 {
				break
			}
		}
		wg.Done()
	}()
	go func() {
		for i := 0; i < 1000; i++ {
			e := trace.Event{Timestamp: i}
			q.Enqueue(&e)
		}
	}()
	wg.Wait()
}
