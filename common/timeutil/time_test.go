package timeutil

import (
	"math"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func TestRoundToClosestN(t *testing.T) {
	tests := []struct {
		name     string
		val      int
		n        int
		expected int
	}{
		{"round up", 110, 50, 100},
		{"round down", 120, 50, 100},
		{"round up to next", 130, 50, 150},
		{"exact multiple", 100, 50, 100},
		{"zero value", 0, 50, 0},
		{"negative value", -110, 50, -100},
		{"negative round up", -120, 50, -100},
		{"small n", 7, 3, 6},
		{"large n", 999, 100, 1000},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := roundToClosestN(tt.val, tt.n)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestGenerateRandomDuration(t *testing.T) {
	t.Run("basic range", func(t *testing.T) {
		min, max := 1, 5
		duration := GenerateRandomDuration(min, max)

		assert.GreaterOrEqual(t, duration, time.Duration(min)*time.Second)
		assert.LessOrEqual(t, duration, time.Duration(max)*time.Second)
	})

	t.Run("single value range", func(t *testing.T) {
		min, max := 3, 3
		duration := GenerateRandomDuration(min, max)

		assert.Equal(t, time.Duration(3)*time.Second, duration)
	})

	t.Run("zero range", func(t *testing.T) {
		min, max := 0, 0
		duration := GenerateRandomDuration(min, max)

		assert.Equal(t, time.Duration(0)*time.Second, duration)
	})

	t.Run("distribution test", func(t *testing.T) {
		// Test that we get different values over multiple calls
		min, max := 1, 10
		seen := make(map[time.Duration]bool)

		// No need to seed - Go 1.20+ automatically seeds the global generator

		for i := 0; i < 50; i++ {
			duration := GenerateRandomDuration(min, max)
			seen[duration] = true

			// Verify range
			assert.GreaterOrEqual(t, duration, time.Duration(min)*time.Second)
			assert.LessOrEqual(t, duration, time.Duration(max)*time.Second)
		}

		// Should see at least a few different values in 50 attempts
		assert.GreaterOrEqual(t, len(seen), 2, "Should generate varied random durations")
	})
}

func TestClockTicksToNsSinceBootTime(t *testing.T) {
	// Note: This function depends on GetUserHZ() which uses CGO
	// We'll test the math assuming UserHZ = 100 (common default)

	tests := []struct {
		name     string
		ticks    uint64
		expected uint64
	}{
		{"zero ticks", 0, 0},
		{"one tick", 1, 10_000_000},           // 1 tick = 10ms = 10,000,000 ns (assuming 100Hz)
		{"100 ticks", 100, 1_000_000_000},     // 100 ticks = 1s = 1,000,000,000 ns
		{"large value", 1000, 10_000_000_000}, // 1000 ticks = 10s
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// We can't easily test this without UserHZ being set
			// But we can test the function exists and returns reasonable values
			result := ClockTicksToNsSinceBootTime(tt.ticks)

			if tt.ticks == 0 {
				assert.Equal(t, uint64(0), result)
			} else {
				// Should be some reasonable conversion
				assert.Greater(t, result, uint64(0))
				// Should be proportional to ticks
				if tt.ticks > 1 {
					result1 := ClockTicksToNsSinceBootTime(1)
					assert.InDelta(t, float64(result1*tt.ticks), float64(result), float64(result1),
						"Result should be roughly proportional to ticks")
				}
			}
		})
	}
}

func TestBootToEpochNS(t *testing.T) {
	tests := []struct {
		name     string
		bootNS   uint64
		expected uint64
	}{
		{"zero boot time", 0, 0},
		{"normal boot time", 1_000_000_000, 1_000_000_000}, // 1 second
		{"large boot time", 1_234_567_890_123_456_789, 1_234_567_890_123_456_789},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Note: This depends on GetBootTimeNS() which requires Init() to be called
			// We'll test the math logic by ensuring the function exists and behaves reasonably
			result := BootToEpochNS(tt.bootNS)

			// Should be at least the boot time value we passed
			assert.GreaterOrEqual(t, result, tt.bootNS)
		})
	}
}

func TestNsSinceEpochToTime(t *testing.T) {
	tests := []struct {
		name     string
		ns       uint64
		expected time.Time
	}{
		{
			"unix epoch",
			0,
			time.Unix(0, 0),
		},
		{
			"specific time",
			1_640_995_200_000_000_000, // 2022-01-01 00:00:00 UTC
			time.Unix(1_640_995_200, 0),
		},
		{
			"with nanoseconds",
			1_640_995_200_123_456_789,
			time.Unix(1_640_995_200, 123_456_789),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := NsSinceEpochToTime(tt.ns)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestNsSinceBootTimeToTime(t *testing.T) {
	tests := []struct {
		name string
		ns   uint64
	}{
		{"zero nanoseconds", 0},
		{"one second", 1_000_000_000},
		{"one minute", 60_000_000_000},
		{"one hour", 3_600_000_000_000},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Note: This depends on GetBootTime() which requires Init() to be called
			result := NsSinceBootTimeToTime(tt.ns)

			// Should return a time (could be zero time if Init not called)
			// If zero nanoseconds and no init, result could be zero time
			if tt.ns == 0 {
				// Zero nanoseconds case - result depends on boot time
				assert.True(t, result.Equal(time.Unix(0, 0)) || result.After(time.Unix(0, 0)))
			} else {
				// Non-zero nanoseconds should always give us a time after epoch
				assert.True(t, result.After(time.Unix(0, 0)) || result.Equal(time.Unix(0, int64(tt.ns))))
			}
		})
	}
}

// Test basic state access functions
func TestStateAccessFunctions(t *testing.T) {
	t.Run("GetStartTimeNS", func(t *testing.T) {
		// Without Init being called, this should return 0
		result := GetStartTimeNS()
		assert.GreaterOrEqual(t, result, int64(0))
	})

	t.Run("GetBootTimeNS", func(t *testing.T) {
		// Without Init being called, this should return 0
		result := GetBootTimeNS()
		assert.GreaterOrEqual(t, result, int64(0))
	})

	t.Run("GetBootTime", func(t *testing.T) {
		// Without Init being called, this should return unix epoch or later
		result := GetBootTime()
		assert.True(t, result.After(time.Unix(0, 0)) || result.Equal(time.Unix(0, 0)))
	})
}

// Test time conversion consistency
func TestTimeConversionConsistency(t *testing.T) {
	t.Run("BootToEpoch and EpochToBoot are inverse", func(t *testing.T) {
		originalBootNS := uint64(1_000_000_000) // 1 second since boot

		// Convert boot to epoch then back to boot
		epochNS := BootToEpochNS(originalBootNS)
		backToBootNS := EpochToBootTimeNS(epochNS)

		// Should get back the original value (within reasonable precision)
		assert.InDelta(t, float64(originalBootNS), float64(backToBootNS), 1000,
			"Boot->Epoch->Boot conversion should be reversible")
	})

	t.Run("NsSinceEpochToTime and Time.UnixNano are consistent", func(t *testing.T) {
		ns := uint64(1_640_995_200_123_456_789) // 2022-01-01 with nanoseconds

		timeFromNS := NsSinceEpochToTime(ns)
		backToNS := uint64(timeFromNS.UnixNano())

		assert.Equal(t, ns, backToNS, "Time conversion should be reversible")
	})
}

// Test system-dependent functions (basic smoke tests)
func TestSystemDependentFunctions(t *testing.T) {
	t.Run("GetUserHZ", func(t *testing.T) {
		// This function uses CGO, but we can test it doesn't crash
		hz := GetUserHZ()

		// USER_HZ should be a positive value, typically 100
		assert.Greater(t, hz, int64(0), "USER_HZ should be positive")
		assert.LessOrEqual(t, hz, int64(10000), "USER_HZ should be reasonable (< 10000)")

		// Should be consistent across calls (cached)
		hz2 := GetUserHZ()
		assert.Equal(t, hz, hz2, "GetUserHZ should return consistent values")
	})

	t.Run("GetSystemHZ basic", func(t *testing.T) {
		// This function uses time.Sleep and /proc/timer_list
		// We can at least test it doesn't crash, though it's slow
		// Note: This test will take ~1 second due to the sleep

		// Test that the function exists and runs
		hz := GetSystemHZ()

		// CONFIG_HZ should be a positive value
		assert.GreaterOrEqual(t, hz, 0, "CONFIG_HZ should be non-negative")

		// Should be a reasonable value (common values are 100, 250, 300, 1000)
		if hz > 0 {
			assert.LessOrEqual(t, hz, 10000, "CONFIG_HZ should be reasonable")
		}

		// Should be consistent across calls (cached)
		hz2 := GetSystemHZ()
		assert.Equal(t, hz, hz2, "GetSystemHZ should return consistent values")
	})

	t.Run("Init with CLOCK_MONOTONIC", func(t *testing.T) {
		// Test Init function with a valid clock
		err := Init(CLOCK_MONOTONIC)

		// Should not error on most systems
		assert.NoError(t, err, "Init with CLOCK_MONOTONIC should succeed")

		// After Init, these should return reasonable values
		startTime := GetStartTimeNS()
		bootTime := GetBootTimeNS()

		assert.GreaterOrEqual(t, startTime, int64(0), "Start time should be non-negative")

		// Boot time can be 0 in containerized environments (like GitHub CI)
		// where monotonic and epoch clocks might be very close
		assert.GreaterOrEqual(t, bootTime, int64(0), "Boot time should be non-negative after Init")

		// If boot time is positive, it should be in the past (before now)
		if bootTime > 0 {
			now := time.Now().UnixNano()
			assert.Less(t, bootTime, now, "Boot time should be before current time")
		} else {
			t.Log("Boot time is 0 (likely containerized environment)")
		}
	})

	t.Run("Init with CLOCK_BOOTTIME", func(t *testing.T) {
		// Test Init function with boottime clock
		err := Init(CLOCK_BOOTTIME)

		// Should not error on most modern systems (may error on very old systems)
		if err != nil {
			t.Logf("CLOCK_BOOTTIME not supported: %v", err)
			return // Skip if not supported
		}

		// After Init, these should return reasonable values
		startTime := GetStartTimeNS()
		bootTime := GetBootTimeNS()

		assert.GreaterOrEqual(t, startTime, int64(0), "Start time should be non-negative")

		// Boot time can be 0 in containerized environments (like GitHub CI)
		// where monotonic and epoch clocks might be very close
		assert.GreaterOrEqual(t, bootTime, int64(0), "Boot time should be non-negative after Init")

		// If boot time is positive, it should be in the past (before now)
		if bootTime > 0 {
			now := time.Now().UnixNano()
			assert.Less(t, bootTime, now, "Boot time should be before current time")
		} else {
			t.Log("Boot time is 0 (likely containerized environment)")
		}
	})
}

// Test constants are defined correctly
func TestConstants(t *testing.T) {
	t.Run("clock constants", func(t *testing.T) {
		// Test that our constants match the expected unix values
		assert.Equal(t, 1, CLOCK_MONOTONIC, "CLOCK_MONOTONIC should equal unix.CLOCK_MONOTONIC")
		assert.Equal(t, 7, CLOCK_BOOTTIME, "CLOCK_BOOTTIME should equal unix.CLOCK_BOOTTIME")
	})
}

// Test error conditions where possible
func TestErrorConditions(t *testing.T) {
	t.Run("Init with invalid clock", func(t *testing.T) {
		// Test with an invalid/unsupported clock ID
		err := Init(-999) // Invalid clock ID

		// May or may not return an error depending on the system
		// The important thing is that it doesn't panic
		if err != nil {
			t.Logf("Init with invalid clock returned expected error: %v", err)
		} else {
			t.Log("Init with invalid clock did not return error (system-dependent behavior)")
		}

		// Should not panic or crash - just calling the function is the test
		assert.NotPanics(t, func() {
			Init(-1000) // Another invalid clock ID
		}, "Init should not panic with invalid clock")
	})
}

//
// Tests for clock-aware procfs conversion (added for PROCTREE clock base consistency fix)
//

// Test_getCurrentSuspendTime validates suspend time is within reasonable bounds.
//
// NOTE: This is an integration test - it reads actual system clocks.
// It validates that getCurrentSuspendTime() returns reasonable values but
// does not test exact calculations since that would just duplicate the syscalls.
func Test_getCurrentSuspendTime(t *testing.T) {
	suspendTime, err := getCurrentSuspendTime()
	assert.NoError(t, err, "getCurrentSuspendTime() should not fail")

	// Suspend time should be reasonable (0 to 30 days worth of nanoseconds)
	maxReasonableSuspend := uint64(30 * 24 * 3600 * 1e9) // 30 days
	assert.LessOrEqual(t, suspendTime, maxReasonableSuspend,
		"Suspend time should be <= 30 days")

	t.Logf("Current system suspend time: %d ns (%.3f seconds)",
		suspendTime, float64(suspendTime)/1e9)
}

// Test_convertBoottimeToMonotonicEpoch tests the BOOTTIME to MONOTONIC conversion
func Test_convertBoottimeToMonotonicEpoch(t *testing.T) {
	tests := []struct {
		name           string
		boottimeEpoch  uint64
		suspendNs      uint64
		expectedResult uint64
	}{
		{
			name:           "Zero timestamp with suspend time",
			boottimeEpoch:  0,
			suspendNs:      1_000_000_000, // 1 second
			expectedResult: 0,             // Should return 0, not underflow
		},
		{
			name:           "Zero timestamp with no suspend time",
			boottimeEpoch:  0,
			suspendNs:      0,
			expectedResult: 0,
		},
		{
			name:           "Small timestamp - underflow protection",
			boottimeEpoch:  1000,
			suspendNs:      5000, // Suspend time > timestamp
			expectedResult: 1000, // Should return as-is, not underflow
		},
		{
			name:           "Normal timestamp with suspend time",
			boottimeEpoch:  1_700_000_000_000_000_000,                 // ~2023-11-14
			suspendNs:      5_000_000_000,                             // 5 seconds suspend
			expectedResult: 1_700_000_000_000_000_000 - 5_000_000_000, // boottime - suspend
		},
		{
			name:           "Normal timestamp with no suspend time",
			boottimeEpoch:  1_700_000_000_000_000_000,
			suspendNs:      0,
			expectedResult: 1_700_000_000_000_000_000, // Should be unchanged
		},
		{
			name:           "Large timestamp with small suspend",
			boottimeEpoch:  math.MaxUint64 / 2,
			suspendNs:      1_000_000_000, // 1 second
			expectedResult: math.MaxUint64/2 - 1_000_000_000,
		},
		{
			name:           "Equal values",
			boottimeEpoch:  1_000_000_000,
			suspendNs:      1_000_000_000,
			expectedResult: 0, // boottime - suspend = 0
		},
		{
			name:           "Typical system values",
			boottimeEpoch:  1_731_787_200_000_000_000,                     // 2024-11-16 20:00:00 UTC
			suspendNs:      3_600_000_000_000,                             // 1 hour suspend
			expectedResult: 1_731_787_200_000_000_000 - 3_600_000_000_000, // boottime - suspend
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := convertBoottimeToMonotonicEpoch(tt.boottimeEpoch, tt.suspendNs)

			assert.Equal(t, tt.expectedResult, result,
				"convertBoottimeToMonotonicEpoch(%d, %d)", tt.boottimeEpoch, tt.suspendNs)

			// Verify invariant: result should never be greater than input
			assert.LessOrEqual(t, result, tt.boottimeEpoch,
				"Result should be <= input (monotonic <= boottime)")
		})
	}
}

// TestProcfsStartTimeToEpochNS tests the main procfs conversion function.
//
// NOTE: It uses actual system time and clocks.
// It validates the conversion logic and clock-specific behavior with real data,
// so it's not synthetic.
func TestProcfsStartTimeToEpochNS(t *testing.T) {
	tests := []struct {
		name          string
		clockID       int32
		startJiffies  uint64
		expectConvert bool // Whether BOOTTIME->MONOTONIC conversion should occur
	}{
		{
			name:          "BOOTTIME clock - no conversion - small jiffies",
			clockID:       CLOCK_BOOTTIME,
			startJiffies:  100, // 1 second @ USER_HZ=100
			expectConvert: false,
		},
		{
			name:          "BOOTTIME clock - no conversion - large jiffies",
			clockID:       CLOCK_BOOTTIME,
			startJiffies:  100000, // 1000 seconds @ USER_HZ=100
			expectConvert: false,
		},
		{
			name:          "MONOTONIC clock - should convert - small jiffies",
			clockID:       CLOCK_MONOTONIC,
			startJiffies:  100,
			expectConvert: true,
		},
		{
			name:          "MONOTONIC clock - should convert - large jiffies",
			clockID:       CLOCK_MONOTONIC,
			startJiffies:  100000,
			expectConvert: true,
		},
		{
			name:          "MONOTONIC clock - zero jiffies",
			clockID:       CLOCK_MONOTONIC,
			startJiffies:  0,
			expectConvert: true,
		},
		{
			name:          "BOOTTIME clock - zero jiffies",
			clockID:       CLOCK_BOOTTIME,
			startJiffies:  0,
			expectConvert: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Reset and initialize with test clock
			initTimeOnce = sync.Once{}
			usedClockID = 0

			err := Init(tt.clockID)
			assert.NoError(t, err, "Init() should not fail")

			// Verify clock ID was stored correctly
			assert.Equal(t, tt.clockID, GetUsedClockID(),
				"Clock ID should be stored correctly")

			// Perform conversion
			result := ProcfsStartTimeToEpochNS(tt.startJiffies)

			// Calculate expected baseline using BOOTTIME boot time
			// (procfs values are always BOOTTIME-based)
			bootNs := ClockTicksToNsSinceBootTime(tt.startJiffies)
			epochBootNs := uint64(GetBootTimeBoottimeNS()) + bootNs

			// Validate result
			if tt.expectConvert {
				// For MONOTONIC: result should be <= epochBootNs (accounting for suspend time)
				assert.LessOrEqual(t, result, epochBootNs,
					"MONOTONIC result should be <= BOOTTIME (accounting for suspend time)")
				t.Logf("MONOTONIC: jiffies=%d -> boottime_epoch=%d, monotonic_epoch=%d (diff=%d)",
					tt.startJiffies, epochBootNs, result, epochBootNs-result)
			} else {
				// For BOOTTIME: result should equal epochBootNs (no conversion)
				assert.Equal(t, epochBootNs, result,
					"BOOTTIME result should equal raw conversion (no conversion needed)")
				t.Logf("BOOTTIME: jiffies=%d -> epoch=%d", tt.startJiffies, result)
			}

			// Additional sanity checks
			if tt.startJiffies == 0 {
				assert.LessOrEqual(t, result, uint64(time.Now().UnixNano()),
					"Zero jiffies should not produce future timestamp")
			}
		})
	}
}
