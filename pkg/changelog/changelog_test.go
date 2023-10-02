package changelog

import (
	"reflect"
	"testing"
	"time"
)

func TestChangelog(t *testing.T) {
	t.Parallel()

	cl := NewChangelog[int]()

	// Test GetCurrent on an empty changelog
	if cl.GetCurrent() != 0 {
		t.Errorf("GetCurrent on empty changelog should return 0")
	}

	// Test SetCurrent and GetCurrent
	cl.SetCurrent(42)
	if cl.GetCurrent() != 42 {
		t.Errorf("GetCurrent after SetCurrent should return 42")
	}

	// Test Get on an empty changelog

	cl = NewChangelog[int]()

	if cl.Get(time.Now()) != 0 {
		t.Errorf("Get on empty changelog should return 0")
	}

	// Test 1 second interval among changes

	cl = NewChangelog[int]()

	cl.SetCurrent(1)
	time.Sleep(2 * time.Second)
	cl.SetCurrent(2)
	time.Sleep(2 * time.Second)
	cl.SetCurrent(3)

	now := time.Now()

	if cl.Get(now.Add(-4*time.Second)) != 1 {
		t.Errorf("Get on changelog should return 1")
	}
	if cl.Get(now.Add(-2*time.Second)) != 2 {
		t.Errorf("Get on changelog should return 2")
	}
	if cl.Get(now) != 3 {
		t.Errorf("Get on changelog should return 3")
	}

	// Test 100 milliseconds interval among changes
	// NOTE: If this test becomes flaky we can change/remove it.

	cl = NewChangelog[int]()

	cl.SetCurrent(1)
	time.Sleep(100 * time.Millisecond)
	cl.SetCurrent(2)
	time.Sleep(100 * time.Millisecond)
	cl.SetCurrent(3)

	now = time.Now()

	if cl.Get(now.Add(-200*time.Millisecond)) != 1 {
		t.Errorf("Get on changelog should return 1")
	}
	if cl.Get(now.Add(-100*time.Millisecond)) != 2 {
		t.Errorf("Get on changelog should return 2")
	}
	if cl.Get(now) != 3 {
		t.Errorf("Get on changelog should return 3")
	}

	// Test getting all values at once

	expected := []int{1, 2, 3}
	if !reflect.DeepEqual(cl.GetAll(), expected) {
		t.Errorf("GetAll should return %v, but got %v", expected, cl.GetAll())
	}
}
