package changelog

import (
	"testing"
	"time"
)

// Test cases where the Changelog needs to enforce the size boundary
var testCasesAllScenarios = []struct {
	value int
	time  time.Time
}{
	{
		value: 42,
		time:  getTimeFromSec(0),
	},
	{
		value: 72,
		time:  getTimeFromSec(1),
	},
	{
		value: 642,
		time:  getTimeFromSec(2),
	},
	{
		value: 672,
		time:  getTimeFromSec(3),
	},
	{
		value: 642,
		time:  getTimeFromSec(4),
	},
	{
		value: 672,
		time:  getTimeFromSec(5),
	},
	{
		value: 6642,
		time:  getTimeFromSec(6),
	},
	{
		value: 672,
		time:  getTimeFromSec(7),
	},
	{
		value: 642,
		time:  getTimeFromSec(8),
	},
	{
		value: 6672,
		time:  getTimeFromSec(9),
	},
	{
		value: 9642,
		time:  getTimeFromSec(10),
	},
	{
		value: 0,
		time:  getTimeFromSec(0),
	},
	{
		value: 0,
		time:  getTimeFromSec(1),
	},
	{
		value: 0,
		time:  getTimeFromSec(2),
	},
	{
		value: 0,
		time:  getTimeFromSec(3),
	},
}

// Test cases where the changelog is within the maximum size limit
var testCasesWithinLimit = []struct {
	value int
	time  time.Time
}{
	{
		value: 0,
		time:  getTimeFromSec(0),
	},
	{
		value: 1,
		time:  getTimeFromSec(1),
	},
	{
		value: 2,
		time:  getTimeFromSec(2),
	},
	{
		value: 3,
		time:  getTimeFromSec(3),
	},
	{
		value: 4,
		time:  getTimeFromSec(4),
	},
	{
		value: 5,
		time:  getTimeFromSec(5),
	},
	{
		value: 6,
		time:  getTimeFromSec(6),
	},
	{
		value: 7,
		time:  getTimeFromSec(7),
	},
	{
		value: 8,
		time:  getTimeFromSec(8),
	},
	{
		value: 9,
		time:  getTimeFromSec(9),
	},
	{
		value: 10,
		time:  getTimeFromSec(10),
	},
	{
		value: 11,
		time:  getTimeFromSec(11),
	},
	{
		value: 12,
		time:  getTimeFromSec(12),
	},
	{
		value: 13,
		time:  getTimeFromSec(13),
	},
	{
		value: 14,
		time:  getTimeFromSec(14),
	},
}

func Benchmark_Set(b *testing.B) {
	b.Run("All Scenarios", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			b.StopTimer()
			clv := NewChangelog[int](3)
			b.StartTimer()
			for _, tc := range testCasesAllScenarios {
				clv.Set(tc.value, tc.time)
			}
		}
	})

	b.Run("Within Limit", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			b.StopTimer()
			clv := NewChangelog[int](15)
			b.StartTimer()
			for _, tc := range testCasesWithinLimit {
				clv.Set(tc.value, tc.time)
			}
		}
	})
}

func Benchmark_Get(b *testing.B) {
	b.Run("All Scenarios", func(b *testing.B) {
		clv := NewChangelog[int](3)
		for _, tc := range testCasesAllScenarios {
			clv.Set(tc.value, tc.time)
		}

		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			for _, tc := range testCasesAllScenarios {
				_ = clv.Get(tc.time)
			}
		}
	})

	b.Run("Within Limit", func(b *testing.B) {
		clv := NewChangelog[int](15)
		for _, tc := range testCasesWithinLimit {
			clv.Set(tc.value, tc.time)
		}

		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			for _, tc := range testCasesWithinLimit {
				_ = clv.Get(tc.time)
			}
		}
	})
}

func Benchmark_GetCurrent(b *testing.B) {
	b.Run("All Scenarios", func(b *testing.B) {
		clv := NewChangelog[int](3)
		for _, tc := range testCasesAllScenarios {
			clv.Set(tc.value, tc.time)
		}

		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			_ = clv.GetCurrent()
		}
	})

	b.Run("Within Limit", func(b *testing.B) {
		clv := NewChangelog[int](15)
		for _, tc := range testCasesWithinLimit {
			clv.Set(tc.value, tc.time)
		}

		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			_ = clv.GetCurrent()
		}
	})
}
