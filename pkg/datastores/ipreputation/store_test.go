package ipreputation

import (
	"fmt"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/types/known/anypb"
	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/aquasecurity/tracee/api/v1beta1/datastores"
)

func TestIPReputationStore_WriteAndRead(t *testing.T) {
	store := NewIPReputationStore(LastWriteWins, nil)

	// Write a reputation
	rep := &IPReputation{
		IP:          "1.2.3.4",
		Status:      ReputationBlacklisted,
		Source:      "test_source",
		Severity:    8,
		Tags:        []string{"malware", "botnet"},
		LastUpdated: time.Now(),
		Metadata:    map[string]string{"info": "test"},
	}

	err := store.WriteReputation("test_source", "1.2.3.4", rep)
	require.NoError(t, err)

	// Read it back
	result, found := store.GetReputation("1.2.3.4")
	require.True(t, found)
	assert.Equal(t, "1.2.3.4", result.IP)
	assert.Equal(t, ReputationBlacklisted, result.Status)
	assert.Equal(t, 8, result.Severity)
	assert.Equal(t, []string{"malware", "botnet"}, result.Tags)
}

func TestIPReputationStore_IsBlacklisted(t *testing.T) {
	store := NewIPReputationStore(LastWriteWins, nil)

	rep := &IPReputation{
		IP:          "1.2.3.4",
		Status:      ReputationBlacklisted,
		Severity:    9,
		LastUpdated: time.Now(),
	}

	err := store.WriteReputation("source1", "1.2.3.4", rep)
	require.NoError(t, err)

	assert.True(t, store.IsBlacklisted("1.2.3.4"))
	assert.False(t, store.IsWhitelisted("1.2.3.4"))
	assert.False(t, store.IsBlacklisted("5.6.7.8"))
}

func TestIPReputationStore_WriteBatch(t *testing.T) {
	store := NewIPReputationStore(LastWriteWins, nil)

	batch := map[string]*IPReputation{
		"1.2.3.4": {
			IP:          "1.2.3.4",
			Status:      ReputationBlacklisted,
			Severity:    8,
			LastUpdated: time.Now(),
		},
		"5.6.7.8": {
			IP:          "5.6.7.8",
			Status:      ReputationWhitelisted,
			Severity:    1,
			LastUpdated: time.Now(),
		},
	}

	err := store.WriteBatch("source1", batch)
	require.NoError(t, err)

	// Check both IPs
	rep1, found1 := store.GetReputation("1.2.3.4")
	require.True(t, found1)
	assert.Equal(t, ReputationBlacklisted, rep1.Status)

	rep2, found2 := store.GetReputation("5.6.7.8")
	require.True(t, found2)
	assert.Equal(t, ReputationWhitelisted, rep2.Status)
}

func TestIPReputationStore_ConflictResolution_LastWriteWins(t *testing.T) {
	store := NewIPReputationStore(LastWriteWins, nil)

	// Write older entry
	older := &IPReputation{
		IP:          "1.2.3.4",
		Status:      ReputationBlacklisted,
		Severity:    5,
		LastUpdated: time.Now().Add(-1 * time.Hour),
	}
	err := store.WriteReputation("source1", "1.2.3.4", older)
	require.NoError(t, err)

	// Write newer entry from different source
	newer := &IPReputation{
		IP:          "1.2.3.4",
		Status:      ReputationWhitelisted,
		Severity:    2,
		LastUpdated: time.Now(),
	}
	err = store.WriteReputation("source2", "1.2.3.4", newer)
	require.NoError(t, err)

	// Should get the newer one
	result, found := store.GetReputation("1.2.3.4")
	require.True(t, found)
	assert.Equal(t, ReputationWhitelisted, result.Status)
	assert.Equal(t, 2, result.Severity)
}

func TestIPReputationStore_ConflictResolution_MaxSeverity(t *testing.T) {
	store := NewIPReputationStore(MaxSeverity, nil)

	// Write low severity
	low := &IPReputation{
		IP:          "1.2.3.4",
		Status:      ReputationSuspicious,
		Severity:    3,
		LastUpdated: time.Now(),
	}
	err := store.WriteReputation("source1", "1.2.3.4", low)
	require.NoError(t, err)

	// Write high severity
	high := &IPReputation{
		IP:          "1.2.3.4",
		Status:      ReputationBlacklisted,
		Severity:    9,
		LastUpdated: time.Now().Add(-1 * time.Hour), // Older but higher severity
	}
	err = store.WriteReputation("source2", "1.2.3.4", high)
	require.NoError(t, err)

	// Should get the higher severity one
	result, found := store.GetReputation("1.2.3.4")
	require.True(t, found)
	assert.Equal(t, ReputationBlacklisted, result.Status)
	assert.Equal(t, 9, result.Severity)
}

func TestIPReputationStore_ConflictResolution_PriorityBased(t *testing.T) {
	priorities := map[string]int{
		"high_priority": 10,
		"low_priority":  1,
	}
	store := NewIPReputationStore(PriorityBased, priorities)

	// Write from low priority source
	low := &IPReputation{
		IP:          "1.2.3.4",
		Status:      ReputationBlacklisted,
		Severity:    9,
		LastUpdated: time.Now(),
	}
	err := store.WriteReputation("low_priority", "1.2.3.4", low)
	require.NoError(t, err)

	// Write from high priority source with lower severity
	high := &IPReputation{
		IP:          "1.2.3.4",
		Status:      ReputationWhitelisted,
		Severity:    2,
		LastUpdated: time.Now().Add(-1 * time.Hour),
	}
	err = store.WriteReputation("high_priority", "1.2.3.4", high)
	require.NoError(t, err)

	// Should get the high priority one
	result, found := store.GetReputation("1.2.3.4")
	require.True(t, found)
	assert.Equal(t, ReputationWhitelisted, result.Status)
	assert.Equal(t, "high_priority", result.Source)
}

func TestIPReputationStore_Delete(t *testing.T) {
	store := NewIPReputationStore(LastWriteWins, nil)

	// Write reputation
	rep := &IPReputation{
		IP:          "1.2.3.4",
		Status:      ReputationBlacklisted,
		Severity:    8,
		LastUpdated: time.Now(),
	}
	err := store.WriteReputation("source1", "1.2.3.4", rep)
	require.NoError(t, err)

	// Verify it exists
	_, found := store.GetReputation("1.2.3.4")
	require.True(t, found)

	// Delete using protobuf key
	keyMsg := &datastores.IPAddressKey{Ip: "1.2.3.4"}
	keyAny, err := anypb.New(keyMsg)
	require.NoError(t, err)

	err = store.Delete("source1", keyAny)
	require.NoError(t, err)

	// Verify it's gone
	_, found = store.GetReputation("1.2.3.4")
	assert.False(t, found)
}

func TestIPReputationStore_ClearSource(t *testing.T) {
	store := NewIPReputationStore(LastWriteWins, nil)

	// Write multiple IPs from same source
	for i := 1; i <= 5; i++ {
		rep := &IPReputation{
			IP:          fmt.Sprintf("1.2.3.%d", i),
			Status:      ReputationBlacklisted,
			Severity:    i,
			LastUpdated: time.Now(),
		}
		err := store.WriteReputation("source1", rep.IP, rep)
		require.NoError(t, err)
	}

	// Write from different source
	rep := &IPReputation{
		IP:          "5.6.7.8",
		Status:      ReputationBlacklisted,
		Severity:    9,
		LastUpdated: time.Now(),
	}
	err := store.WriteReputation("source2", "5.6.7.8", rep)
	require.NoError(t, err)

	// Clear source1
	err = store.ClearSource("source1")
	require.NoError(t, err)

	// Verify source1 IPs are gone
	for i := 1; i <= 5; i++ {
		_, found := store.GetReputation(fmt.Sprintf("1.2.3.%d", i))
		assert.False(t, found, "IP from source1 should be deleted")
	}

	// Verify source2 IP still exists
	_, found := store.GetReputation("5.6.7.8")
	assert.True(t, found, "IP from source2 should still exist")
}

func TestIPReputationStore_ListSources(t *testing.T) {
	store := NewIPReputationStore(LastWriteWins, nil)

	// Write from multiple sources
	sources := []string{"source1", "source2", "source3"}
	for _, source := range sources {
		rep := &IPReputation{
			IP:          "1.2.3.4",
			Status:      ReputationBlacklisted,
			Severity:    8,
			LastUpdated: time.Now(),
		}
		err := store.WriteReputation(source, "1.2.3.4", rep)
		require.NoError(t, err)
	}

	// List sources
	listedSources, err := store.ListSources()
	require.NoError(t, err)
	assert.ElementsMatch(t, sources, listedSources)
}

func TestIPReputationStore_WriteValue_Protobuf(t *testing.T) {
	store := NewIPReputationStore(LastWriteWins, nil)

	// Create protobuf messages
	keyMsg := &datastores.IPAddressKey{Ip: "1.2.3.4"}
	repMsg := &datastores.IPReputation{
		Status:      datastores.ReputationStatus_REPUTATION_BLACKLISTED,
		Severity:    8,
		Tags:        []string{"malware", "c2"},
		LastUpdated: timestamppb.Now(),
		Metadata:    map[string]string{"source_url": "https://example.com"},
	}

	keyAny, err := anypb.New(keyMsg)
	require.NoError(t, err)
	dataAny, err := anypb.New(repMsg)
	require.NoError(t, err)

	entry := &datastores.DataEntry{
		Key:  keyAny,
		Data: dataAny,
	}

	// Write via protobuf interface
	err = store.WriteValue("test_source", entry)
	require.NoError(t, err)

	// Verify it was written
	result, found := store.GetReputation("1.2.3.4")
	require.True(t, found)
	assert.Equal(t, ReputationBlacklisted, result.Status)
	assert.Equal(t, 8, result.Severity)
	assert.Equal(t, []string{"malware", "c2"}, result.Tags)
}

func TestIPReputationStore_WriteBatchValues_Protobuf(t *testing.T) {
	store := NewIPReputationStore(LastWriteWins, nil)

	// Create batch entries
	entries := []*datastores.DataEntry{}
	for i := 1; i <= 3; i++ {
		keyMsg := &datastores.IPAddressKey{Ip: fmt.Sprintf("1.2.3.%d", i)}
		repMsg := &datastores.IPReputation{
			Status:      datastores.ReputationStatus_REPUTATION_BLACKLISTED,
			Severity:    int32(i),
			LastUpdated: timestamppb.Now(),
		}

		keyAny, err := anypb.New(keyMsg)
		require.NoError(t, err)
		dataAny, err := anypb.New(repMsg)
		require.NoError(t, err)

		entries = append(entries, &datastores.DataEntry{
			Key:  keyAny,
			Data: dataAny,
		})
	}

	// Write batch
	err := store.WriteBatchValues("test_source", entries)
	require.NoError(t, err)

	// Verify all were written
	for i := 1; i <= 3; i++ {
		result, found := store.GetReputation(fmt.Sprintf("1.2.3.%d", i))
		require.True(t, found)
		assert.Equal(t, i, result.Severity)
	}
}

func TestIPReputationStore_InvalidSeverity(t *testing.T) {
	store := NewIPReputationStore(LastWriteWins, nil)

	tests := []struct {
		name     string
		severity int
		wantErr  bool
	}{
		{"valid_low", 1, false},
		{"valid_mid", 5, false},
		{"valid_high", 10, false},
		{"invalid_zero", 0, true},
		{"invalid_negative", -1, true},
		{"invalid_too_high", 11, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rep := &IPReputation{
				IP:          "1.2.3.4",
				Status:      ReputationBlacklisted,
				Severity:    tt.severity,
				LastUpdated: time.Now(),
			}

			err := store.WriteReputation("source1", "1.2.3.4", rep)
			if tt.wantErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestIPReputationStore_CheckIPs(t *testing.T) {
	store := NewIPReputationStore(LastWriteWins, nil)

	// Write multiple IPs
	ips := []string{"1.2.3.1", "1.2.3.2", "1.2.3.3"}
	for _, ip := range ips {
		rep := &IPReputation{
			IP:          ip,
			Status:      ReputationBlacklisted,
			Severity:    8,
			LastUpdated: time.Now(),
		}
		err := store.WriteReputation("source1", ip, rep)
		require.NoError(t, err)
	}

	// Check batch including one that doesn't exist
	checkIPs := []string{"1.2.3.1", "1.2.3.2", "1.2.3.99"}
	results := store.CheckIPs(checkIPs)

	assert.Len(t, results, 2, "Should return only found IPs")
	assert.Contains(t, results, "1.2.3.1")
	assert.Contains(t, results, "1.2.3.2")
	assert.NotContains(t, results, "1.2.3.99")
}

func TestIPReputationStore_GetMetrics(t *testing.T) {
	store := NewIPReputationStore(LastWriteWins, nil)

	// Initially empty
	metrics := store.GetMetrics()
	assert.Equal(t, int64(0), metrics.ItemCount)

	// Write some data
	for i := 1; i <= 5; i++ {
		rep := &IPReputation{
			IP:          fmt.Sprintf("1.2.3.%d", i),
			Status:      ReputationBlacklisted,
			Severity:    8,
			LastUpdated: time.Now(),
		}
		err := store.WriteReputation("source1", rep.IP, rep)
		require.NoError(t, err)
	}

	// Check metrics
	metrics = store.GetMetrics()
	assert.Equal(t, int64(5), metrics.ItemCount)
	assert.False(t, metrics.LastAccess.IsZero())
}

func TestIPReputationStore_ThreadSafety(t *testing.T) {
	store := NewIPReputationStore(LastWriteWins, nil)

	// Concurrent writes
	done := make(chan bool)
	for i := 0; i < 10; i++ {
		go func(id int) {
			for j := 0; j < 100; j++ {
				ip := fmt.Sprintf("1.2.3.%d", id)
				rep := &IPReputation{
					Status:      ReputationBlacklisted,
					Severity:    (id % 10) + 1,
					LastUpdated: time.Now(),
				}
				_ = store.WriteReputation(fmt.Sprintf("source%d", id), ip, rep)
			}
			done <- true
		}(i)
	}

	// Wait for all goroutines
	for i := 0; i < 10; i++ {
		<-done
	}

	// Concurrent reads
	for i := 0; i < 10; i++ {
		go func(id int) {
			for j := 0; j < 100; j++ {
				_, _ = store.GetReputation(fmt.Sprintf("1.2.3.%d", id))
			}
			done <- true
		}(i)
	}

	// Wait for all goroutines
	for i := 0; i < 10; i++ {
		<-done
	}

	// Should not crash and should have data
	metrics := store.GetMetrics()
	assert.Greater(t, metrics.ItemCount, int64(0))
}
