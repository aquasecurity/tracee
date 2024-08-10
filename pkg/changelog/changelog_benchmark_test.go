package changelog

import (
	"testing"
	"time"
)

func Benchmark_enforceSizeBoundary(b *testing.B) {
	testCases := []struct {
		name      string
		changelog Changelog[int]
	}{
		{
			name: "No change needed",
			changelog: Changelog[int]{
				changes: []item[int]{
					{value: 1, timestamp: getTimeFromSec(1)},
					{value: 2, timestamp: getTimeFromSec(2)},
				},
				timestamps: map[time.Time]struct{}{
					getTimeFromSec(1): {},
					getTimeFromSec(2): {},
				},
				maxSize: 5,
			},
		},
		{
			name: "Trim excess with duplicates",
			changelog: Changelog[int]{
				changes: []item[int]{
					{value: 1, timestamp: getTimeFromSec(1)},
					{value: 1, timestamp: getTimeFromSec(2)},
					{value: 2, timestamp: getTimeFromSec(3)},
					{value: 3, timestamp: getTimeFromSec(4)},
					{value: 3, timestamp: getTimeFromSec(5)},
				},
				timestamps: map[time.Time]struct{}{
					getTimeFromSec(1): {},
					getTimeFromSec(2): {},
					getTimeFromSec(3): {},
					getTimeFromSec(4): {},
					getTimeFromSec(5): {},
				},
				maxSize: 3,
			},
		},
		{
			name: "Remove oldest entries",
			changelog: Changelog[int]{
				changes: []item[int]{
					{value: 1, timestamp: getTimeFromSec(1)},
					{value: 2, timestamp: getTimeFromSec(2)},
					{value: 3, timestamp: getTimeFromSec(3)},
					{value: 4, timestamp: getTimeFromSec(4)},
				},
				timestamps: map[time.Time]struct{}{
					getTimeFromSec(1): {},
					getTimeFromSec(2): {},
					getTimeFromSec(3): {},
					getTimeFromSec(4): {},
				},
				maxSize: 2,
			},
		},
	}

	for _, tc := range testCases {
		b.Run(tc.name, func(b *testing.B) {
			for i := 0; i < b.N; i++ {
				clv := tc.changelog // Create a copy for each iteration
				clv.enforceSizeBoundary()
			}
		})
	}
}

func Benchmark_setAt(b *testing.B) {
	// Test cases where the Changelog needs to enforce the size boundary
	testCasesAllScenarios := []struct {
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
			time:  getTimeFromSec(3), // will trigger removal of oldest entry
		},
		{
			value: 642,
			time:  getTimeFromSec(4), // will trigger coalescing of duplicate values
		},
		{
			value: 672,
			time:  getTimeFromSec(5), // will trigger coalescing of duplicate values
		},
		{
			value: 6642,
			time:  getTimeFromSec(6), // will trigger removal of oldest entry
		},
		{
			value: 672,
			time:  getTimeFromSec(7), // will trigger coalescing of duplicate values
		},
		{
			value: 642,
			time:  getTimeFromSec(8), // will trigger coalescing of duplicate values
		},
		{
			value: 6672,
			time:  getTimeFromSec(9), // will trigger removal of oldest entry
		},
		{
			value: 9642,
			time:  getTimeFromSec(10), // will trigger removal of oldest entry
		},
		{
			value: 0,
			time:  getTimeFromSec(0), // will just update the value
		},
		{
			value: 0,
			time:  getTimeFromSec(1), // will just update the value
		},
		{
			value: 0,
			time:  getTimeFromSec(2), // will just update the value
		},
		{
			value: 0,
			time:  getTimeFromSec(3), // will just update the value
		},
	}

	b.Run("All Scenarios", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			b.StopTimer()
			clv := NewChangelog[int](3)
			b.StartTimer()
			for _, tc := range testCasesAllScenarios {
				clv.setAt(tc.value, tc.time)
			}
		}
	})

	// Test cases where the changelog is within the maximum size limit
	testCasesWithinLimit := []struct {
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

	b.Run("Within Limit", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			b.StopTimer()
			clv := NewChangelog[int](15)
			b.StartTimer()
			for _, tc := range testCasesWithinLimit {
				clv.setAt(tc.value, tc.time)
			}
		}
	})
}
