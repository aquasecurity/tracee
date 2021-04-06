package helpers

import (
	"sync"
	"testing"
)

func TestRWArrayWrite(t *testing.T) {
	a := NewRWArray(1024)

	last := 0

	for i := 0; i < 1000; i++ {
		slot1 := a.Put(&i)
		if slot1 < 0 {
			t.Errorf("failed to put")
		}

		if last != slot1 {
			t.Fatalf("Put didn't occupy first available; expected=%v, got=%v", last, slot1)
		}

		slot2 := a.Put(&i)
		if slot2 < 0 {
			t.Fatalf("failed to put")
		}

		if slot1 >= slot2 {
			t.Fatalf("slot1 (%v) < slot2 (%v)", slot1, slot2)
		}

		a.Remove(uint(slot2))

		last = slot2
	}
}

func TestRWArrayExhaust(t *testing.T) {
	a := NewRWArray(1024)

	last := -1

	for {
		v := 123
		slot := a.Put(&v)

		if slot < 0 {
			if uint(last) != a.Capacity()-1 {
				t.Fatalf("failed to put, last=%v", last)
			}
			return
		}

		if slot != last+1 {
			t.Fatalf("Put returned non-sequential slot; expected=%v, got=%v", last+1, slot)
		}

		last = slot
	}
}

func TestRWArrayRead(t *testing.T) {
	a := NewRWArray(1024)

	for i := 0; i < 1000; i++ {
		v := i
		slot := a.Put(&v)
		if slot != i {
			t.Errorf("Put returned non-sequential slot; expected=%v, got=%v", i, slot)
		}
	}

	for i := 0; i < 1000; i++ {
		v := a.Get(uint(i)).(*int)
		if *v != i {
			t.Errorf("Get returned wrong valuue; expected=%v, got=%v", i, *v)
		}
	}
}

// Designed to be run under race detector
func TestRWArrayConcurrent(t *testing.T) {
	a := NewRWArray(16 * 1024)
	capacity := a.Capacity()

	stop := make(chan struct{})
	wg := sync.WaitGroup{}

	// Populate every other slot
	v := 123
	for i := uint(0); i < capacity; i++ {
		a.Put(&v)
	}
	for i := uint(1); i < capacity; i += 2 {
		a.Remove(i)
	}

	writer := func() {
		for {
			// fill the holes
			for i := uint(0); i < capacity/2; i++ {
				a.Put(&v)
			}

			// make some holes
			for i := uint(1); i < capacity; i += 2 {
				a.Remove(i)
			}

			// time to exit?
			select {
			case _, _ = <-stop:
				return
			default:
			}
		}
	}

	reader := func() {
		for rounds := 0; rounds < 10; rounds++ {
			for i := uint(0); i < capacity; i += 2 {
				a.Get(i)
			}
		}

		wg.Done()
	}

	go writer()

	wg.Add(3)
	go reader()
	go reader()
	go reader()

	wg.Wait()
	close(stop)
}
