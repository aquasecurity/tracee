package changelog

import (
	"fmt"
	"os"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"

	"github.com/aquasecurity/tracee/pkg/utils/tests"
)

func getTimeFromSec(second int) time.Time {
	return time.Unix(int64(second), 0)
}

func TestChangelog_GetZeroValue(t *testing.T) {
	changelog := NewChangelog[int](1)
	time0 := getTimeFromSec(0)

	// Assert zero value before any set
	assert.Equal(t, 0, changelog.Get(time0), "Expected zero value for testInt0")
	assert.Equal(t, 0, changelog.GetCurrent(), "Expected zero value for testInt0")

	// Set and assert value
	changelog.Set(3001, time0)
	assert.Equal(t, 3001, changelog.Get(time0), "Expected testInt0 to be 3001")
	assert.Equal(t, 3001, changelog.GetCurrent(), "Expected current testInt0 to be 3001")

	// Check the count of entries
	assert.Equal(t, 1, changelog.Count(), "Expected 1 entry")
}

func TestChangelog_ShiftAndReplace(t *testing.T) {
	changelog := NewChangelog[string](2)

	// Set entries and assert initial values
	changelog.Set("initial", getTimeFromSec(0))
	changelog.Set("updated", getTimeFromSec(1))
	assert.Equal(t, "initial", changelog.Get(getTimeFromSec(0)), "Expected first entry to be 'initial'")
	assert.Equal(t, "updated", changelog.Get(getTimeFromSec(1)), "Expected second entry to be 'updated'")

	// Test shifting and replacement
	changelog.Set("final", getTimeFromSec(2))
	assert.Equal(t, "updated", changelog.Get(getTimeFromSec(1)), "Expected oldest entry to be removed")
	assert.Equal(t, "final", changelog.Get(getTimeFromSec(2)), "Expected newest entry to be 'final'")
	assert.Equal(t, "final", changelog.GetCurrent(), "Expected current entry to be 'final'")

	// Check the count of entries
	assert.Equal(t, 2, changelog.Count(), "Expected 2 entries")
}

func TestChangelog_ReplaceMostRecentWithSameValue(t *testing.T) {
	changelog := NewChangelog[string](2)

	// Set entries and assert initial value
	changelog.Set("initial", getTimeFromSec(0))
	assert.Equal(t, "initial", changelog.Get(getTimeFromSec(0)), "Expected first entry to be 'initial'")
	changelog.Set("initial", getTimeFromSec(1))
	assert.Equal(t, "initial", changelog.Get(getTimeFromSec(1)), "Expected first entry to have timestamp updated")

	// Test replacement of most recent entry with same value
	changelog.Set("second", getTimeFromSec(2))
	assert.Equal(t, "initial", changelog.Get(getTimeFromSec(1)), "Expected first entry to be 'initial'")
	assert.Equal(t, "second", changelog.Get(getTimeFromSec(2)), "Expected second entry to have timestamp updated")

	// Check the count of entries
	assert.Equal(t, 2, changelog.Count(), "Expected 2 entries")
}

func TestChangelog_InsertWithOlderTimestamp(t *testing.T) {
	changelog := NewChangelog[string](3)
	now := getTimeFromSec(0)

	// Insert entries with increasing timestamps
	changelog.Set("first", now)
	changelog.Set("second", now.Add(1*time.Second))
	changelog.Set("third", now.Add(2*time.Second))

	// Insert an entry with an older timestamp
	changelog.Set("older", now.Add(1*time.Millisecond))

	// Check the count of entries
	assert.Equal(t, 3, changelog.Count(), "Expected 3 entries")

	// Verify the order of entries
	assert.Equal(t, "older", changelog.Get(now.Add(1*time.Millisecond)), "Expected 'older' to be the first entry")
	assert.Equal(t, "second", changelog.Get(now.Add(1*time.Second)), "Expected 'second' to be the second entry")
	assert.Equal(t, "third", changelog.Get(now.Add(2*time.Second)), "Expected 'third' to be the last entry")

	// Insert an entry with an intermediate timestamp
	changelog.Set("second-third", now.Add(1*time.Second+1*time.Millisecond))

	// Verify the order of entries
	assert.Equal(t, "older", changelog.Get(now.Add(1*time.Millisecond)), "Expected 'older' to be the first entry")
	assert.Equal(t, "second-third", changelog.Get(now.Add(1*time.Second+1*time.Millisecond)), "Expected 'second-third' to be the second entry")
	assert.Equal(t, "third", changelog.Get(now.Add(2*time.Second)), "Expected 'third' to be the last entry")

	// Check the count of entries
	assert.Equal(t, 3, changelog.Count(), "Expected 3 entries")
}

func TestChangelog_InsertSameValueWithNewTimestamp(t *testing.T) {
	changelog := NewChangelog[string](3)

	// Insert entries with increasing timestamps
	changelog.Set("same", getTimeFromSec(0))

	// Replace the last entry with the same value but a new timestamp
	changelog.Set("same", getTimeFromSec(1))

	// Verify the order of entries
	assert.Equal(t, "same", changelog.Get(getTimeFromSec(1)), "Expected 'same' to be the second entry")

	// Insert entries with sequential timestamps
	changelog.Set("new", getTimeFromSec(2))
	changelog.Set("other", getTimeFromSec(3))

	// Replace the last entry with the same value but a new timestamp
	changelog.Set("other", getTimeFromSec(4))

	// Verify the order of entries
	assert.Equal(t, "same", changelog.Get(getTimeFromSec(1)), "Expected 'same' to be the first entry")
	assert.Equal(t, "new", changelog.Get(getTimeFromSec(2)), "Expected 'new' to be the second entry")
	assert.Equal(t, "other", changelog.Get(getTimeFromSec(4)), "Expected 'other' to be the last entry")

	// Check the count of entries
	assert.Equal(t, 3, changelog.Count(), "Expected 3 entries")
}

func TestChangelog_StructType(t *testing.T) {
	type testStruct struct {
		A int
		B string
	}

	changelog := NewChangelog[testStruct](3)
	now := getTimeFromSec(0)

	// Insert an entry
	tsFirst := testStruct{A: 1, B: "first"}
	changelog.Set(tsFirst, now)

	// Verify the entry
	assert.Equal(t, tsFirst, changelog.Get(now), fmt.Sprintf("Expected %v", tsFirst))

	// Check the count of entries
	assert.Equal(t, 1, changelog.Count(), "Expected 1 entry")

	// Insert a new entry
	tsSecond := testStruct{A: 2, B: "second"}
	changelog.Set(tsSecond, now.Add(1*time.Second))

	// Verify the entry
	assert.Equal(t, tsSecond, changelog.Get(now.Add(1*time.Second)), fmt.Sprintf("Expected %v", tsSecond))

	// Check the count of entries
	assert.Equal(t, 2, changelog.Count(), "Expected 2 entries")

	// Insert a new entry
	tsThird := testStruct{A: 3, B: "third"}
	changelog.Set(tsThird, now.Add(2*time.Second))

	// Verify the entry
	assert.Equal(t, tsThird, changelog.Get(now.Add(2*time.Second)), fmt.Sprintf("Expected %v", tsThird))

	// Check the count of entries
	assert.Equal(t, 3, changelog.Count(), "Expected 3 entries")

	// Insert a new entry
	tsFourth := testStruct{A: 4, B: "fourth"}
	changelog.Set(tsFourth, now.Add(3*time.Second))

	// Verify the entry
	assert.Equal(t, tsFourth, changelog.Get(now.Add(3*time.Second)), fmt.Sprintf("Expected %v", tsFourth))

	// Check the count of entries
	assert.Equal(t, 3, changelog.Count(), "Expected 3 entries")

	// Verify the order of entries
	assert.Equal(t, tsSecond, changelog.Get(now.Add(1*time.Second)), fmt.Sprintf("Expected %v", tsSecond))
	assert.Equal(t, tsThird, changelog.Get(now.Add(2*time.Second)), fmt.Sprintf("Expected %v", tsThird))
	assert.Equal(t, tsFourth, changelog.Get(now.Add(3*time.Second)), fmt.Sprintf("Expected %v", tsFourth))
	assert.Equal(t, tsFourth, changelog.GetCurrent(), fmt.Sprintf("Expected %v", tsFourth))
}

// TestChangelog_PrintSizes prints the sizes of the structs used in the Changelog type.
// Run it as DEBUG test to see the output.
func TestChangelog_PrintSizes(t *testing.T) {
	changelog1 := NewChangelog[int](1)
	tests.PrintStructSizes(t, os.Stdout, changelog1)

	entry1 := entry[int]{}
	tests.PrintStructSizes(t, os.Stdout, entry1)

	//

	changelog2 := NewChangelog[string](1)
	tests.PrintStructSizes(t, os.Stdout, changelog2)

	entry2 := entry[string]{}
	tests.PrintStructSizes(t, os.Stdout, entry2)
}
