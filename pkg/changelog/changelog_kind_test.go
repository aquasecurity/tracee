package changelog

import (
	"os"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"

	"github.com/aquasecurity/tracee/pkg/utils"
)

const (
	// int members
	testInt0 MemberKind = iota
	testInt1
	testInt2
)

const (
	// string members
	testString MemberKind = iota
)

func getTimeFromSec(second int) time.Time {
	return time.Unix(int64(second), 0)
}

func TestChangelogKind_GetZeroValue(t *testing.T) {
	flags := []MaxEntries{
		testInt0: 1,
	}
	changelog := NewChangelogKind[int](flags)
	time0 := getTimeFromSec(0)

	// Assert zero value before any set
	assert.Equal(t, 0, changelog.Get(testInt0, time0), "Expected zero value for testInt0")
	assert.Equal(t, 0, changelog.GetCurrent(testInt0), "Expected zero value for testInt0")

	// Set and assert value
	changelog.Set(testInt0, 3001, time0)
	assert.Equal(t, 3001, changelog.Get(testInt0, time0), "Expected testInt0 to be 3001")
	assert.Equal(t, 3001, changelog.GetCurrent(testInt0), "Expected current testInt0 to be 3001")

	// Check the count of entries
	assert.Equal(t, 1, changelog.Count(testInt0), "Expected 1 entry")
	assert.Equal(t, 0, changelog.Count(testInt1), "Expected 0 entries")
}

func TestChangelogKind_ShiftAndReplace(t *testing.T) {
	flags := []MaxEntries{
		testString: 2,
	}
	changelog := NewChangelogKind[string](flags)

	// Set entries and assert initial values
	changelog.Set(testString, "initial", getTimeFromSec(0))
	changelog.Set(testString, "updated", getTimeFromSec(1))
	assert.Equal(t, "initial", changelog.Get(testString, getTimeFromSec(0)), "Expected first entry to be 'initial'")
	assert.Equal(t, "updated", changelog.Get(testString, getTimeFromSec(1)), "Expected second entry to be 'updated'")

	// Test shifting and replacement
	changelog.Set(testString, "final", getTimeFromSec(2))
	assert.Equal(t, "updated", changelog.Get(testString, getTimeFromSec(1)), "Expected oldest entry to be removed")
	assert.Equal(t, "final", changelog.Get(testString, getTimeFromSec(2)), "Expected newest entry to be 'final'")
	assert.Equal(t, "final", changelog.GetCurrent(testString), "Expected current entry to be 'final'")

	// Check the count of entries
	assert.Equal(t, 2, changelog.Count(testString), "Expected 2 entries")
}

func TestChangelogKind_ReplaceMostRecentWithSameValue(t *testing.T) {
	flags := []MaxEntries{
		testString: 2,
	}
	changelog := NewChangelogKind[string](flags)

	// Set entries and assert initial value
	changelog.Set(testString, "initial", getTimeFromSec(0))
	assert.Equal(t, "initial", changelog.Get(testString, getTimeFromSec(0)), "Expected first entry to be 'initial'")
	changelog.Set(testString, "initial", getTimeFromSec(1))
	assert.Equal(t, "initial", changelog.Get(testString, getTimeFromSec(1)), "Expected first entry to have timestamp updated")

	// Test replacement of most recent entry with same value
	changelog.Set(testString, "second", getTimeFromSec(2))
	assert.Equal(t, "initial", changelog.Get(testString, getTimeFromSec(1)), "Expected first entry to be 'initial'")
	assert.Equal(t, "second", changelog.Get(testString, getTimeFromSec(2)), "Expected second entry to have timestamp updated")

	// Check the count of entries
	assert.Equal(t, 2, changelog.Count(testString), "Expected 2 entries")
}

func TestChangelogKind_InsertWithOlderTimestamp(t *testing.T) {
	flags := []MaxEntries{
		testString: 3,
	}
	changelog := NewChangelogKind[string](flags)
	now := getTimeFromSec(0)

	// Insert entries with increasing timestamps
	changelog.Set(testString, "first", now)
	changelog.Set(testString, "second", now.Add(1*time.Second))
	changelog.Set(testString, "third", now.Add(2*time.Second))

	// Insert an entry with an older timestamp
	changelog.Set(testString, "older", now.Add(1*time.Millisecond))

	// Check the count of entries
	assert.Equal(t, 3, changelog.Count(testString), "Expected 3 entries")

	// Verify the order of entries
	assert.Equal(t, "older", changelog.Get(testString, now.Add(1*time.Millisecond)), "Expected 'older' to be the first entry")
	assert.Equal(t, "second", changelog.Get(testString, now.Add(1*time.Second)), "Expected 'second' to be the second entry")
	assert.Equal(t, "third", changelog.Get(testString, now.Add(2*time.Second)), "Expected 'third' to be the last entry")

	// Insert an entry with an intermediate timestamp
	changelog.Set(testString, "second-third", now.Add(1*time.Second+1*time.Millisecond))

	// Verify the order of entries
	assert.Equal(t, "older", changelog.Get(testString, now.Add(1*time.Millisecond)), "Expected 'older' to be the first entry")
	assert.Equal(t, "second-third", changelog.Get(testString, now.Add(1*time.Second+1*time.Millisecond)), "Expected 'second-third' to be the second entry")
	assert.Equal(t, "third", changelog.Get(testString, now.Add(2*time.Second)), "Expected 'third' to be the last entry")

	// Check the count of entries
	assert.Equal(t, 3, changelog.Count(testString), "Expected 3 entries")
}

func TestChangelogKind_InsertSameValueWithNewTimestamp(t *testing.T) {
	flags := []MaxEntries{
		testString: 3,
	}
	changelog := NewChangelogKind[string](flags)

	// Insert entries with increasing timestamps
	changelog.Set(testString, "same", getTimeFromSec(0))

	// Replace the last entry with the same value but a new timestamp
	changelog.Set(testString, "same", getTimeFromSec(1))

	// Verify the order of entries
	assert.Equal(t, "same", changelog.Get(testString, getTimeFromSec(1)), "Expected 'same' to be the second entry")

	// Insert entries with sequential timestamps
	changelog.Set(testString, "new", getTimeFromSec(2))
	changelog.Set(testString, "other", getTimeFromSec(3))

	// Replace the last entry with the same value but a new timestamp
	changelog.Set(testString, "other", getTimeFromSec(4))

	// Verify the order of entries
	assert.Equal(t, "same", changelog.Get(testString, getTimeFromSec(1)), "Expected 'same' to be the first entry")
	assert.Equal(t, "new", changelog.Get(testString, getTimeFromSec(2)), "Expected 'new' to be the second entry")
	assert.Equal(t, "other", changelog.Get(testString, getTimeFromSec(4)), "Expected 'other' to be the last entry")

	// Check the count of entries
	assert.Equal(t, 3, changelog.Count(testString), "Expected 3 entries")
}

// TestChangelogKind_PrintSizes prints the sizes of the structs used in the ChangelogKind type.
// Run it as DEBUG test to see the output.
func TestChangelogKind_PrintSizes(t *testing.T) {
	flags := []MaxEntries{
		testInt0: 1,
	}

	changelog1 := NewChangelogKind[int](flags)
	utils.PrintStructSizes(os.Stdout, changelog1)

	entryList1 := entryList[int]{
		maxEntries: flags[testInt0],
		entries:    []entry[int]{},
	}
	utils.PrintStructSizes(os.Stdout, entryList1)

	entry1 := entry[int]{}
	utils.PrintStructSizes(os.Stdout, entry1)

	//

	flags = []MaxEntries{
		testString: 1,
	}

	changelog2 := NewChangelogKind[string](flags)
	utils.PrintStructSizes(os.Stdout, changelog2)

	entryList2 := entryList[string]{
		maxEntries: flags[testString],
		entries:    []entry[string]{},
	}
	utils.PrintStructSizes(os.Stdout, entryList2)

	entry2 := entry[string]{}
	utils.PrintStructSizes(os.Stdout, entry2)
}
