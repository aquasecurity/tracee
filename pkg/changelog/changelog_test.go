package changelog_test

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"

	"github.com/aquasecurity/tracee/pkg/changelog"
)

func TestChangelog(t *testing.T) {
	t.Parallel()

	t.Run("GetCurrent on an empty changelog", func(t *testing.T) {
		cl := changelog.NewChangelog[int](3)

		// Test GetCurrent on an empty changelog
		assert.Zero(t, cl.GetCurrent())
	})

	t.Run("Set and get", func(t *testing.T) {
		cl := changelog.NewChangelog[int](3)
		testVal := 42

		cl.SetCurrent(testVal)
		assert.Equal(t, testVal, cl.GetCurrent())
	})

	t.Run("Get on an empty changelog", func(t *testing.T) {
		cl := changelog.NewChangelog[int](3)

		assert.Zero(t, cl.GetCurrent())
	})

	t.Run("Test 1 second interval among changes", func(t *testing.T) {
		cl := changelog.NewChangelog[int](3)

		cl.SetCurrent(1)
		time.Sleep(2 * time.Second)
		cl.SetCurrent(2)
		time.Sleep(2 * time.Second)
		cl.SetCurrent(3)

		now := time.Now()

		assert.Equal(t, 1, cl.Get(now.Add(-4*time.Second)))
		assert.Equal(t, 2, cl.Get(now.Add(-2*time.Second)))
		assert.Equal(t, 3, cl.Get(now))
	})

	t.Run("Test 100 milliseconds interval among changes", func(t *testing.T) {
		cl := changelog.NewChangelog[int](3)

		cl.SetCurrent(1)
		time.Sleep(100 * time.Millisecond)
		cl.SetCurrent(2)
		time.Sleep(100 * time.Millisecond)
		cl.SetCurrent(3)

		now := time.Now()

		assert.Equal(t, 1, cl.Get(now.Add(-200*time.Millisecond)))
		assert.Equal(t, 2, cl.Get(now.Add(-100*time.Millisecond)))
		assert.Equal(t, 3, cl.Get(now))
	})

	t.Run("Test getting all values at once", func(t *testing.T) {
		cl := changelog.NewChangelog[int](3)

		cl.SetCurrent(1)
		time.Sleep(100 * time.Millisecond)
		cl.SetCurrent(2)
		time.Sleep(100 * time.Millisecond)
		cl.SetCurrent(3)

		expected := []int{1, 2, 3}
		assert.Equal(t, expected, cl.GetAll())
	})

	t.Run("Pass max size wit repeated values", func(t *testing.T) {
		cl := changelog.NewChangelog[int](3)

		cl.SetCurrent(1)
		time.Sleep(100 * time.Millisecond)
		cl.SetCurrent(2)
		time.Sleep(100 * time.Millisecond)
		cl.SetCurrent(2)
		time.Sleep(100 * time.Millisecond)
		cl.SetCurrent(3)

		now := time.Now()
		assert.Equal(t, 1, cl.Get(now.Add(-300*time.Millisecond)))
		assert.Equal(t, 2, cl.Get(now.Add(-200*time.Millisecond)))
		assert.Equal(t, 2, cl.Get(now.Add(-100*time.Millisecond)))
		assert.Equal(t, 3, cl.Get(now))
		assert.Len(t, cl.GetAll(), 3)
	})

	t.Run("Pass max size with unique values", func(t *testing.T) {
		cl := changelog.NewChangelog[int](3)

		cl.SetCurrent(1)
		time.Sleep(100 * time.Millisecond)
		cl.SetCurrent(2)
		time.Sleep(100 * time.Millisecond)
		cl.SetCurrent(3)
		time.Sleep(100 * time.Millisecond)
		cl.SetCurrent(4)

		now := time.Now()
		assert.Equal(t, 0, cl.Get(now.Add(-300*time.Millisecond)))
		assert.Equal(t, 2, cl.Get(now.Add(-200*time.Millisecond)))
		assert.Equal(t, 3, cl.Get(now.Add(-100*time.Millisecond)))
		assert.Equal(t, 4, cl.Get(now.Add(time.Millisecond)))
		assert.Len(t, cl.GetAll(), 3)
	})

	t.Run("Pass max size with new old value", func(t *testing.T) {
		cl := changelog.NewChangelog[int](3)

		cl.SetCurrent(1)
		time.Sleep(100 * time.Millisecond)
		cl.SetCurrent(2)
		time.Sleep(100 * time.Millisecond)
		cl.SetCurrent(3)

		now := time.Now()
		cl.Set(4, now.Add(-400*time.Millisecond))

		// Make sure that the new value was not added
		assert.Equal(t, 0, cl.Get(now.Add(-300*time.Millisecond)))

		// Sanity check
		assert.Equal(t, 1, cl.Get(now.Add(-200*time.Millisecond)))
		assert.Equal(t, 2, cl.Get(now.Add(-100*time.Millisecond)))
		assert.Equal(t, 3, cl.Get(now))
		assert.Len(t, cl.GetAll(), 3)
	})

	t.Run("Zero sized changelog", func(t *testing.T) {
		cl := changelog.NewChangelog[int](0)

		cl.SetCurrent(1)
		time.Sleep(100 * time.Millisecond)
		cl.SetCurrent(2)
		time.Sleep(100 * time.Millisecond)
		cl.SetCurrent(3)

		now := time.Now()
		cl.Set(4, now.Add(-400*time.Millisecond))

		// Make sure that the new value was not added

		// Sanity check
		assert.Equal(t, 0, cl.Get(now.Add(-300*time.Millisecond)))
		assert.Equal(t, 0, cl.Get(now.Add(-200*time.Millisecond)))
		assert.Equal(t, 0, cl.Get(now.Add(-100*time.Millisecond)))
		assert.Equal(t, 0, cl.Get(now))
		assert.Empty(t, cl.GetAll())
	})
}
