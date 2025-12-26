package system

import (
	"testing"
)

func TestGetMemoryStats(t *testing.T) {
	stats := GetMemoryStats()

	// Basic sanity checks - memory stats should be non-zero
	if stats.Alloc == 0 {
		t.Error("Expected Alloc to be non-zero")
	}
	if stats.Sys == 0 {
		t.Error("Expected Sys to be non-zero")
	}

	// TotalAlloc should be at least as much as current Alloc
	if stats.TotalAlloc < stats.Alloc {
		t.Errorf("Expected TotalAlloc (%d) to be >= Alloc (%d)", stats.TotalAlloc, stats.Alloc)
	}

	// RSS might be 0 on some systems where /proc/self/status is not readable
	// so we won't fail the test, but we'll log it
	t.Logf("Memory stats: Alloc=%d, TotalAlloc=%d, Sys=%d, RSS=%d, NumGC=%d",
		stats.Alloc, stats.TotalAlloc, stats.Sys, stats.RSS, stats.NumGC)
}

func TestGetCPUStats(t *testing.T) {
	stats, err := GetCPUStats()
	if err != nil {
		t.Fatalf("GetCPUStats failed: %v", err)
	}

	// Basic sanity checks
	if stats.Cores <= 0 {
		t.Errorf("Expected Cores to be positive, got %d", stats.Cores)
	}
	if stats.Uptime <= 0 {
		t.Errorf("Expected Uptime to be positive, got %f", stats.Uptime)
	}

	t.Logf("CPU stats: UserTime=%d, SystemTime=%d, Uptime=%f, Cores=%d",
		stats.UserTime, stats.SystemTime, stats.Uptime, stats.Cores)
}

func TestCalculateCPUUsagePercent(t *testing.T) {
	tests := []struct {
		name     string
		previous CPUStats
		current  CPUStats
		expected float64
	}{
		{
			name:     "first measurement (empty previous)",
			previous: CPUStats{},
			current: CPUStats{
				UserTime:   1000,
				SystemTime: 500,
				Uptime:     10.0,
				Cores:      4,
			},
			expected: 0.0,
		},
		{
			name: "zero time difference",
			previous: CPUStats{
				UserTime:   1000,
				SystemTime: 500,
				Uptime:     10.0,
				Cores:      4,
			},
			current: CPUStats{
				UserTime:   1000,
				SystemTime: 500,
				Uptime:     10.0,
				Cores:      4,
			},
			expected: 0.0,
		},
		{
			name: "negative time difference",
			previous: CPUStats{
				UserTime:   1000,
				SystemTime: 500,
				Uptime:     10.0,
				Cores:      4,
			},
			current: CPUStats{
				UserTime:   1000,
				SystemTime: 500,
				Uptime:     9.0, // time went backwards
				Cores:      4,
			},
			expected: 0.0,
		},
		{
			name: "normal usage calculation",
			previous: CPUStats{
				UserTime:   1000,
				SystemTime: 500,
				Uptime:     10.0,
				Cores:      4,
			},
			current: CPUStats{
				UserTime:   1200, // +200 ticks
				SystemTime: 600,  // +100 ticks
				Uptime:     12.0, // +2 seconds
				Cores:      4,
			},
			// Total CPU time: 300 ticks = 3 seconds (at 100 ticks/second)
			// Wall time: 2 seconds
			// CPU usage: (3/2) * 100 = 150%
			expected: 150.0,
		},
		{
			name: "low usage calculation",
			previous: CPUStats{
				UserTime:   1000,
				SystemTime: 500,
				Uptime:     10.0,
				Cores:      4,
			},
			current: CPUStats{
				UserTime:   1010, // +10 ticks
				SystemTime: 510,  // +10 ticks
				Uptime:     12.0, // +2 seconds
				Cores:      4,
			},
			// Total CPU time: 20 ticks = 0.2 seconds
			// Wall time: 2 seconds
			// CPU usage: (0.2/2) * 100 = 10%
			expected: 10.0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := CalculateCPUUsagePercent(tt.previous, tt.current)

			// Use a small epsilon for floating point comparison
			epsilon := 0.001
			if result < tt.expected-epsilon || result > tt.expected+epsilon {
				t.Errorf("Expected CPU usage %f, got %f", tt.expected, result)
			}
		})
	}
}

// TestGetCPUStatsConsistency verifies that consecutive calls return increasing values
func TestGetCPUStatsConsistency(t *testing.T) {
	first, err := GetCPUStats()
	if err != nil {
		t.Fatalf("First GetCPUStats call failed: %v", err)
	}

	// Do some work to ensure CPU time increases
	sum := 0
	for i := 0; i < 100000; i++ {
		sum += i
	}

	second, err := GetCPUStats()
	if err != nil {
		t.Fatalf("Second GetCPUStats call failed: %v", err)
	}

	// Uptime should increase or stay the same (might not change in very short intervals)
	if second.Uptime < first.Uptime {
		t.Errorf("Expected uptime to not decrease: first=%f, second=%f", first.Uptime, second.Uptime)
	}

	// CPU time should increase or stay the same (might not change in very short intervals)
	firstTotal := first.UserTime + first.SystemTime
	secondTotal := second.UserTime + second.SystemTime
	if secondTotal < firstTotal {
		t.Errorf("Expected CPU time to not decrease: first=%d, second=%d", firstTotal, secondTotal)
	}

	// Cores should be consistent
	if first.Cores != second.Cores {
		t.Errorf("Expected consistent core count: first=%d, second=%d", first.Cores, second.Cores)
	}

	// Calculate usage
	usage := CalculateCPUUsagePercent(first, second)
	if usage < 0 {
		t.Errorf("Expected non-negative CPU usage, got %f", usage)
	}

	t.Logf("CPU usage between measurements: %f%% (used %d for work)", usage, sum)
}

// TestGetMemoryStatsConsistency verifies memory stats are reasonable
func TestGetMemoryStatsConsistency(t *testing.T) {
	stats := GetMemoryStats()

	// Allocate some memory
	data := make([]byte, 1024*1024) // 1MB
	for i := range data {
		data[i] = byte(i % 256)
	}

	newStats := GetMemoryStats()

	// TotalAlloc should have increased
	if newStats.TotalAlloc <= stats.TotalAlloc {
		t.Errorf("Expected TotalAlloc to increase after allocation: before=%d, after=%d",
			stats.TotalAlloc, newStats.TotalAlloc)
	}

	// Current alloc might not necessarily increase due to GC, but total should
	t.Logf("Memory before allocation: Alloc=%d, TotalAlloc=%d", stats.Alloc, stats.TotalAlloc)
	t.Logf("Memory after allocation: Alloc=%d, TotalAlloc=%d", newStats.Alloc, newStats.TotalAlloc)
	t.Logf("Allocated data length: %d", len(data))
}

// TestGetRSSMemoryIntegration tests the RSS memory functionality indirectly
func TestGetRSSMemoryIntegration(t *testing.T) {
	// Test that RSS memory is included in memory stats
	stats := GetMemoryStats()

	// RSS should be reasonable compared to other memory stats
	if stats.RSS > 0 {
		// RSS should not be dramatically larger than allocated memory
		// (allowing for some overhead, but not 100x difference)
		if stats.RSS > stats.Alloc*100 {
			t.Logf("Warning: RSS (%d) is much larger than Alloc (%d)", stats.RSS, stats.Alloc)
		}

		// RSS should be at least some reasonable minimum (1KB)
		if stats.RSS < 1024 {
			t.Errorf("RSS seems too small: %d bytes", stats.RSS)
		}
	} else {
		t.Log("RSS is 0, possibly /proc/self/status is not readable")
	}
}

// BenchmarkGetCPUStats benchmarks the CPU stats collection
func BenchmarkGetCPUStats(b *testing.B) {
	for i := 0; i < b.N; i++ {
		_, err := GetCPUStats()
		if err != nil {
			b.Fatalf("GetCPUStats failed: %v", err)
		}
	}
}

// BenchmarkGetMemoryStats benchmarks the memory stats collection
func BenchmarkGetMemoryStats(b *testing.B) {
	for i := 0; i < b.N; i++ {
		_ = GetMemoryStats()
	}
}

// BenchmarkCalculateCPUUsagePercent benchmarks the CPU usage calculation
func BenchmarkCalculateCPUUsagePercent(b *testing.B) {
	previous := CPUStats{UserTime: 1000, SystemTime: 500, Uptime: 10.0, Cores: 4}
	current := CPUStats{UserTime: 1200, SystemTime: 600, Uptime: 12.0, Cores: 4}

	for i := 0; i < b.N; i++ {
		_ = CalculateCPUUsagePercent(previous, current)
	}
}
