package changelog

import (
	"reflect"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func TestChangelog(t *testing.T) {
	t.Parallel()

	t.Run("GetCurrent on an empty changelog", func(t *testing.T) {
		cl := NewChangelog[int](3)

		// Test GetCurrent on an empty changelog
		assert.Zero(t, cl.GetCurrent())
	})

	t.Run("Set and get", func(t *testing.T) {
		cl := NewChangelog[int](3)
		testVal := 42

		cl.SetCurrent(testVal)
		assert.Equal(t, testVal, cl.GetCurrent())
	})

	t.Run("Set and get on set time", func(t *testing.T) {
		cl := NewChangelog[int](3)
		testVal1 := 42
		testVal2 := 76
		testVal3 := 76

		// Test with 3 stages of the changelog to make sure the binary search works well for
		// different lengths (both odd and even).
		now := time.Now()
		cl.Set(testVal1, now)
		assert.Equal(t, testVal1, cl.Get(now))

		cl.Set(testVal2, now.Add(time.Second))
		assert.Equal(t, testVal1, cl.Get(now))
		assert.Equal(t, testVal2, cl.Get(now.Add(time.Second)))

		cl.Set(testVal3, now.Add(2*time.Second))
		assert.Equal(t, testVal1, cl.Get(now))
		assert.Equal(t, testVal2, cl.Get(now.Add(time.Second)))
		assert.Equal(t, testVal3, cl.Get(now.Add(2*time.Second)))
	})

	t.Run("Set twice on the same time", func(t *testing.T) {
		cl := NewChangelog[int](3)
		testVal := 42

		now := time.Now()
		cl.Set(testVal, now)
		cl.Set(testVal, now)
		assert.Equal(t, testVal, cl.Get(now))
		assert.Len(t, cl.GetAll(), 1)
		assert.Equal(t, testVal, cl.Get(now))
	})

	t.Run("Get on an empty changelog", func(t *testing.T) {
		cl := NewChangelog[int](3)

		assert.Zero(t, cl.GetCurrent())
	})

	t.Run("Test 1 second interval among changes", func(t *testing.T) {
		cl := NewChangelog[int](3)

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
		cl := NewChangelog[int](3)

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
		cl := NewChangelog[int](3)

		cl.SetCurrent(1)
		time.Sleep(100 * time.Millisecond)
		cl.SetCurrent(2)
		time.Sleep(100 * time.Millisecond)
		cl.SetCurrent(3)

		expected := []int{1, 2, 3}
		assert.Equal(t, expected, cl.GetAll())
	})

	t.Run("Pass max size wit repeated values", func(t *testing.T) {
		cl := NewChangelog[int](3)

		cl.SetCurrent(1)
		time.Sleep(100 * time.Millisecond)
		cl.SetCurrent(2)
		time.Sleep(100 * time.Millisecond)
		cl.SetCurrent(2)
		time.Sleep(100 * time.Millisecond)
		cl.SetCurrent(3)

		now := time.Now()
		assert.Equal(t, 1, cl.Get(now.Add(-300*time.Millisecond)))
		assert.Equal(t, 1, cl.Get(now.Add(-200*time.Millisecond))) // oldest 2 is removed, so 1 is returned
		assert.Equal(t, 2, cl.Get(now.Add(-100*time.Millisecond)))
		assert.Equal(t, 3, cl.Get(now))
		assert.Len(t, cl.GetAll(), 3)
	})

	t.Run("Pass max size with unique values", func(t *testing.T) {
		cl := NewChangelog[int](3)

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
		cl := NewChangelog[int](3)

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
		cl := NewChangelog[int](0)

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

	t.Run("Test enforceSizeBoundary", func(t *testing.T) {
		type TestCase struct {
			name               string
			maxSize            int
			initialChanges     []item[int]
			expectedChanges    []item[int]
			expectedTimestamps map[time.Time]struct{}
		}

		testCases := []TestCase{
			{
				name:    "No Action Required",
				maxSize: 3,
				initialChanges: []item[int]{
					{timestamp: getTimeFromSec(42), value: 1},
					{timestamp: getTimeFromSec(43), value: 2},
					{timestamp: getTimeFromSec(44), value: 3},
				},
				expectedChanges: []item[int]{
					{timestamp: getTimeFromSec(42), value: 1},
					{timestamp: getTimeFromSec(43), value: 2},
					{timestamp: getTimeFromSec(44), value: 3},
				},
				expectedTimestamps: map[time.Time]struct{}{
					getTimeFromSec(42): {},
					getTimeFromSec(43): {},
					getTimeFromSec(44): {},
				},
			},
			{
				name:    "Basic Removal of Oldest Entries",
				maxSize: 3,
				initialChanges: []item[int]{
					{timestamp: getTimeFromSec(42), value: 1},
					{timestamp: getTimeFromSec(43), value: 2},
					{timestamp: getTimeFromSec(44), value: 3},
					{timestamp: getTimeFromSec(45), value: 4},
				},
				expectedChanges: []item[int]{
					{timestamp: getTimeFromSec(43), value: 2},
					{timestamp: getTimeFromSec(44), value: 3},
					{timestamp: getTimeFromSec(45), value: 4},
				},
				expectedTimestamps: map[time.Time]struct{}{
					getTimeFromSec(43): {},
					getTimeFromSec(44): {},
					getTimeFromSec(45): {},
				},
			},
			{
				name:    "Compacting Duplicate Values - Start",
				maxSize: 3,
				initialChanges: []item[int]{
					{timestamp: getTimeFromSec(42), value: 1},
					{timestamp: getTimeFromSec(43), value: 1},
					{timestamp: getTimeFromSec(44), value: 2},
					{timestamp: getTimeFromSec(45), value: 3},
				},
				expectedChanges: []item[int]{
					{timestamp: getTimeFromSec(43), value: 1},
					{timestamp: getTimeFromSec(44), value: 2},
					{timestamp: getTimeFromSec(45), value: 3},
				},
				expectedTimestamps: map[time.Time]struct{}{
					getTimeFromSec(43): {},
					getTimeFromSec(44): {},
					getTimeFromSec(45): {},
				},
			},
			{
				name:    "Compacting Duplicate Values - Middle",
				maxSize: 3,
				initialChanges: []item[int]{
					{timestamp: getTimeFromSec(42), value: 1},
					{timestamp: getTimeFromSec(43), value: 2},
					{timestamp: getTimeFromSec(44), value: 2},
					{timestamp: getTimeFromSec(45), value: 3},
				},
				expectedChanges: []item[int]{
					{timestamp: getTimeFromSec(42), value: 1},
					{timestamp: getTimeFromSec(44), value: 2},
					{timestamp: getTimeFromSec(45), value: 3},
				},
				expectedTimestamps: map[time.Time]struct{}{
					getTimeFromSec(42): {},
					getTimeFromSec(44): {},
					getTimeFromSec(45): {},
				},
			},
			{
				name:    "Compacting Duplicate Values - End",
				maxSize: 3,
				initialChanges: []item[int]{
					{timestamp: getTimeFromSec(42), value: 1},
					{timestamp: getTimeFromSec(43), value: 2},
					{timestamp: getTimeFromSec(44), value: 3},
					{timestamp: getTimeFromSec(45), value: 3},
				},
				expectedChanges: []item[int]{
					{timestamp: getTimeFromSec(42), value: 1},
					{timestamp: getTimeFromSec(43), value: 2},
					{timestamp: getTimeFromSec(45), value: 3},
				},
				expectedTimestamps: map[time.Time]struct{}{
					getTimeFromSec(42): {},
					getTimeFromSec(43): {},
					getTimeFromSec(45): {},
				},
			},
			{
				name:    "Combination of Compaction and Removal of Oldest Entries",
				maxSize: 3,
				initialChanges: []item[int]{
					{timestamp: getTimeFromSec(42), value: 1},
					{timestamp: getTimeFromSec(43), value: 2},
					{timestamp: getTimeFromSec(44), value: 2},
					{timestamp: getTimeFromSec(45), value: 2},
					{timestamp: getTimeFromSec(46), value: 3},
					{timestamp: getTimeFromSec(47), value: 4},
				},
				expectedChanges: []item[int]{
					{timestamp: getTimeFromSec(45), value: 2},
					{timestamp: getTimeFromSec(46), value: 3},
					{timestamp: getTimeFromSec(47), value: 4},
				},
				expectedTimestamps: map[time.Time]struct{}{
					getTimeFromSec(45): {},
					getTimeFromSec(46): {},
					getTimeFromSec(47): {},
				},
			},
		}

		for _, tc := range testCases {
			t.Run(tc.name, func(t *testing.T) {
				cl := NewChangelog[int](tc.maxSize)
				for _, change := range tc.initialChanges {
					cl.Set(change.value, change.timestamp)
				}

				cl.enforceSizeBoundary()

				eq := reflect.DeepEqual(cl.timestamps, tc.expectedTimestamps)
				assert.True(t, eq)

				eq = reflect.DeepEqual(cl.changes, tc.expectedChanges)
				assert.True(t, eq)
			})
		}
	})
}

func getTimeFromSec(second int) time.Time {
	return time.Unix(int64(second), 0)
}
