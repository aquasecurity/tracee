package detectors

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/types/known/anypb"
	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/aquasecurity/tracee/api/v1beta1"
	"github.com/aquasecurity/tracee/api/v1beta1/datastores"
	"github.com/aquasecurity/tracee/api/v1beta1/detection"
)

// TestDetectorToDetectorCommunication validates the core use case where one detector
// writes to a writable data store and another detector reads from it.
// This demonstrates inter-detector communication via shared data stores.
func TestDetectorToDetectorCommunication(t *testing.T) {
	t.Run("ThreatIntelligenceSharing", func(t *testing.T) {
		ctx := context.Background()
		registry := newTestDataStoreRegistry()

		// Simulate DetectorA: Threat Intelligence Collector
		// This detector registers a writable IP reputation store and populates it
		detectorA := &threatIntelDetector{
			id:   "threat_intel_collector",
			name: "Threat Intel Collector",
		}

		paramsA := detection.DetectorParams{
			Logger:     &mockLogger{},
			DataStores: registry,
			Config:     detection.NewEmptyDetectorConfig(),
		}

		err := detectorA.Init(paramsA)
		require.NoError(t, err, "DetectorA should initialize successfully")

		// DetectorA processes events and writes threat intelligence
		maliciousIPEvent := &v1beta1.Event{
			Name:      "security_alert",
			Timestamp: timestamppb.New(time.Now()),
			Data: []*v1beta1.EventValue{
				v1beta1.NewStringValue("src_ip", "192.168.1.100"),
				v1beta1.NewInt32Value("severity", 9),
				v1beta1.NewStringValue("tags", "malware,c2"),
			},
		}

		_, err = detectorA.OnEvent(ctx, maliciousIPEvent)
		require.NoError(t, err, "DetectorA should process event successfully")

		// Write additional threat intelligence
		detectorA.IngestThreatIntel("external_feed", []ipThreatData{
			{IP: "10.0.0.50", Severity: 7, Tags: []string{"suspicious"}},
			{IP: "172.16.0.5", Severity: 10, Tags: []string{"ransomware"}},
		})

		// Simulate DetectorB: Network Connection Analyzer
		// This detector accesses the same store for read-only lookups
		detectorB := &networkAnalyzerDetector{
			id:   "network_analyzer",
			name: "Network Analyzer",
		}

		paramsB := detection.DetectorParams{
			Logger:     &mockLogger{},
			DataStores: registry,
			Config:     detection.NewEmptyDetectorConfig(),
		}

		err = detectorB.Init(paramsB)
		require.NoError(t, err, "DetectorB should initialize successfully")

		// DetectorB processes network connection events and checks them against the threat intel store
		testCases := []struct {
			ip               string
			expectDetection  bool
			expectedSeverity int32
		}{
			{"192.168.1.100", true, 9},
			{"10.0.0.50", true, 7},
			{"172.16.0.5", true, 10},
			{"8.8.8.8", false, 0}, // Clean IP
		}

		for _, tc := range testCases {
			// Create a network connection event
			networkEvent := &v1beta1.Event{
				Name:      "net_packet_tcp",
				Timestamp: timestamppb.New(time.Now()),
				Data: []*v1beta1.EventValue{
					v1beta1.NewStringValue("dst_ip", tc.ip),
					v1beta1.NewInt32Value("dst_port", 443),
				},
			}

			// DetectorB processes the event and checks against threat intel
			outputs, err := detectorB.OnEvent(ctx, networkEvent)
			require.NoError(t, err, "DetectorB should process event without error")

			if tc.expectDetection {
				require.Len(t, outputs, 1, "Should produce detection for malicious IP %s", tc.ip)

				// Verify the detection contains the expected severity
				var severityVal int32
				var foundSeverity bool
				for _, field := range outputs[0].Data {
					if field.Name == "severity" {
						severityVal = field.GetInt32()
						foundSeverity = true
						break
					}
				}
				assert.True(t, foundSeverity, "Detection should contain severity")
				assert.Equal(t, tc.expectedSeverity, severityVal,
					"Detection severity should match for IP %s", tc.ip)

				// Verify IP is in the detection
				var detectedIP string
				var foundIP bool
				for _, field := range outputs[0].Data {
					if field.Name == "malicious_ip" {
						detectedIP = field.GetStr()
						foundIP = true
						break
					}
				}
				assert.True(t, foundIP, "Detection should contain malicious_ip")
				assert.Equal(t, tc.ip, detectedIP)
			} else {
				assert.Len(t, outputs, 0, "Should not produce detection for clean IP %s", tc.ip)
			}
		}

		// Verify DetectorB can see all sources that DetectorA wrote
		sources := detectorB.ListThreatSources()
		assert.Contains(t, sources, "local_detector",
			"DetectorB should see local detector feed")
		assert.Contains(t, sources, "external_feed",
			"DetectorB should see external feed")
	})

	t.Run("MultipleWriters_OwnershipModel", func(t *testing.T) {
		ctx := context.Background()
		registry := newTestDataStoreRegistry()

		// Create two detectors that both try to register the same store
		detector1 := &threatIntelDetector{
			id:   "detector1",
			name: "Detector 1",
		}
		detector2 := &threatIntelDetector{
			id:   "detector2",
			name: "Detector 2",
		}

		params1 := detection.DetectorParams{
			Logger:     &mockLogger{},
			DataStores: registry,
			Config:     detection.NewEmptyDetectorConfig(),
		}
		params2 := detection.DetectorParams{
			Logger:     &mockLogger{},
			DataStores: registry,
			Config:     detection.NewEmptyDetectorConfig(),
		}

		// First detector registers the store
		err := detector1.Init(params1)
		require.NoError(t, err)

		// Second detector tries to register the same store (should fail)
		err = detector2.Init(params2)
		assert.Error(t, err, "Second detector should not be able to register duplicate store")
		assert.Contains(t, err.Error(), "already registered")

		// But detector2 can still access the store for reading
		store, err := registry.GetCustom("ip_reputation")
		require.NoError(t, err)
		require.NotNil(t, store)

		// Detector1 (owner) can write
		detector1.IngestThreatIntel("feed1", []ipThreatData{
			{IP: "1.2.3.4", Severity: 5, Tags: []string{"spam"}},
		})

		// Detector2 can read what detector1 wrote (via separate reader detector)
		reader := &networkAnalyzerDetector{
			id:   "reader",
			name: "Reader",
		}
		readerParams := detection.DetectorParams{
			Logger:     &mockLogger{},
			DataStores: registry,
			Config:     detection.NewEmptyDetectorConfig(),
		}
		err = reader.Init(readerParams)
		require.NoError(t, err)

		// Reader processes a network event and should detect the malicious IP
		networkEvent := &v1beta1.Event{
			Name:      "net_packet_tcp",
			Timestamp: timestamppb.New(time.Now()),
			Data: []*v1beta1.EventValue{
				v1beta1.NewStringValue("dst_ip", "1.2.3.4"),
				v1beta1.NewInt32Value("dst_port", 80),
			},
		}

		outputs, err := reader.OnEvent(ctx, networkEvent)
		require.NoError(t, err)
		require.Len(t, outputs, 1, "Should detect malicious IP")

		// Verify detection details
		var detectedIP string
		var severity int32
		for _, field := range outputs[0].Data {
			if field.Name == "malicious_ip" {
				detectedIP = field.GetStr()
			}
			if field.Name == "severity" {
				severity = field.GetInt32()
			}
		}
		assert.Equal(t, "1.2.3.4", detectedIP)
		assert.Equal(t, int32(5), severity)
	})

	t.Run("GracefulDegradation_StoreUnavailable", func(t *testing.T) {
		ctx := context.Background()
		registry := newTestDataStoreRegistry()

		// Create a detector that depends on a store that doesn't exist
		detector := &networkAnalyzerDetector{
			id:   "network_analyzer",
			name: "Network Analyzer",
		}

		params := detection.DetectorParams{
			Logger:     &mockLogger{},
			DataStores: registry,
			Config:     detection.NewEmptyDetectorConfig(),
		}

		// Init should succeed even without the store (graceful degradation)
		err := detector.Init(params)
		require.NoError(t, err, "Detector should handle missing optional store")

		// Process an event - should gracefully handle unavailable store
		networkEvent := &v1beta1.Event{
			Name:      "net_packet_tcp",
			Timestamp: timestamppb.New(time.Now()),
			Data: []*v1beta1.EventValue{
				v1beta1.NewStringValue("dst_ip", "1.2.3.4"),
				v1beta1.NewInt32Value("dst_port", 443),
			},
		}

		outputs, err := detector.OnEvent(ctx, networkEvent)
		require.NoError(t, err, "Should handle event without store")
		assert.Len(t, outputs, 0, "Should not produce detections when store unavailable")
	})

	t.Run("BatchOperations", func(t *testing.T) {
		ctx := context.Background()
		registry := newTestDataStoreRegistry()

		detector := &threatIntelDetector{
			id:   "threat_intel_collector",
			name: "Threat Intel Collector",
		}

		params := detection.DetectorParams{
			Logger:     &mockLogger{},
			DataStores: registry,
			Config:     detection.NewEmptyDetectorConfig(),
		}

		err := detector.Init(params)
		require.NoError(t, err)

		// Write a large batch of threat intelligence
		batch := make([]ipThreatData, 1000)
		for i := 0; i < 1000; i++ {
			batch[i] = ipThreatData{
				IP:       fmt.Sprintf("10.0.%d.%d", i/256, i%256),
				Severity: (i % 10) + 1,
				Tags:     []string{"test"},
			}
		}

		err = detector.IngestThreatIntel("bulk_feed", batch)
		require.NoError(t, err, "Batch write should succeed")

		// Verify random samples from the batch
		analyzer := &networkAnalyzerDetector{
			id:   "network_analyzer",
			name: "Network Analyzer",
		}
		analyzerParams := detection.DetectorParams{
			Logger:     &mockLogger{},
			DataStores: registry,
			Config:     detection.NewEmptyDetectorConfig(),
		}
		err = analyzer.Init(analyzerParams)
		require.NoError(t, err)

		testIPs := []string{
			"10.0.0.0",
			"10.0.1.255",
			"10.0.3.231",
		}

		for _, ip := range testIPs {
			networkEvent := &v1beta1.Event{
				Name:      "net_packet_tcp",
				Timestamp: timestamppb.New(time.Now()),
				Data: []*v1beta1.EventValue{
					v1beta1.NewStringValue("dst_ip", ip),
					v1beta1.NewInt32Value("dst_port", 443),
				},
			}

			outputs, err := analyzer.OnEvent(ctx, networkEvent)
			require.NoError(t, err)
			assert.Len(t, outputs, 1, "IP %s should be detected from batch", ip)
		}
	})
}

// ipThreatData represents threat intelligence for an IP address
type ipThreatData struct {
	IP       string
	Severity int
	Tags     []string
}

// threatIntelDetector simulates a detector that collects threat intelligence
// and writes it to a shared data store
type threatIntelDetector struct {
	id      string
	name    string
	logger  detection.Logger
	ipStore datastores.WritableStore
}

func (d *threatIntelDetector) GetDefinition() detection.DetectorDefinition {
	return detection.DetectorDefinition{
		ID: d.id,
		ProducedEvent: v1beta1.EventDefinition{
			Name:        d.name,
			Description: "Threat intelligence detector",
		},
		Requirements: detection.DetectorRequirements{
			Events: []detection.EventRequirement{
				{Name: "security_alert", Dependency: detection.DependencyOptional},
			},
		},
	}
}

func (d *threatIntelDetector) Init(params detection.DetectorParams) error {
	d.logger = params.Logger

	// Register writable IP reputation store
	store := newTestIPReputationStore()

	if err := params.DataStores.RegisterWritableStore("ip_reputation", store); err != nil {
		return err
	}

	d.ipStore = store
	return nil
}

func (d *threatIntelDetector) OnEvent(ctx context.Context, event *v1beta1.Event) ([]detection.DetectorOutput, error) {
	// Extract IP and severity from event
	srcIP, found := v1beta1.GetData[string](event, "src_ip")
	if !found {
		return nil, nil
	}

	severity, found := v1beta1.GetData[int32](event, "severity")
	if !found {
		severity = 5 // Default
	}

	tags, _ := v1beta1.GetData[string](event, "tags")

	// Write to store
	store, ok := d.ipStore.(*testIPReputationStore)
	if !ok {
		return nil, nil
	}
	store.Write("local_detector", srcIP, int(severity), parseTagString(tags))

	return nil, nil
}

func (d *threatIntelDetector) Close() error {
	return nil
}

func (d *threatIntelDetector) IngestThreatIntel(source string, threats []ipThreatData) error {
	store, ok := d.ipStore.(*testIPReputationStore)
	if !ok {
		return errors.New("invalid store type")
	}

	for _, threat := range threats {
		store.Write(source, threat.IP, threat.Severity, threat.Tags)
	}

	return nil
}

// networkAnalyzerDetector simulates a detector that reads from the shared store
type networkAnalyzerDetector struct {
	id      string
	name    string
	logger  detection.Logger
	ipStore datastores.DataStore
}

func (d *networkAnalyzerDetector) GetDefinition() detection.DetectorDefinition {
	return detection.DetectorDefinition{
		ID: d.id,
		ProducedEvent: v1beta1.EventDefinition{
			Name:        d.name,
			Description: "Network analyzer detector",
		},
		Requirements: detection.DetectorRequirements{
			Events: []detection.EventRequirement{
				{Name: "net_packet_tcp", Dependency: detection.DependencyOptional},
			},
		},
	}
}

func (d *networkAnalyzerDetector) Init(params detection.DetectorParams) error {
	d.logger = params.Logger

	// Access the store as read-only via GetCustom
	store, err := params.DataStores.GetCustom("ip_reputation")
	if err != nil {
		// Store not available - graceful degradation
		d.logger.Warnw("IP reputation store not available, degrading gracefully")
		return nil // Optional dependency
	}

	d.ipStore = store
	return nil
}

func (d *networkAnalyzerDetector) OnEvent(ctx context.Context, event *v1beta1.Event) ([]detection.DetectorOutput, error) {
	// Extract destination IP from the network event
	dstIP, found := v1beta1.GetData[string](event, "dst_ip")
	if !found {
		return nil, nil
	}

	// Check the IP against the threat intelligence store
	isMalicious, severity := d.CheckIP(dstIP)
	if !isMalicious {
		return nil, nil // No detection for clean IPs
	}

	// Create detection data
	data := []*v1beta1.EventValue{
		v1beta1.NewStringValue("malicious_ip", dstIP),
		v1beta1.NewInt32Value("severity", int32(severity)),
		v1beta1.NewStringValue("src_event", event.Name),
	}

	return []detection.DetectorOutput{{Data: data}}, nil
}

func (d *networkAnalyzerDetector) Close() error {
	return nil
}

func (d *networkAnalyzerDetector) CheckIP(ip string) (isMalicious bool, severity int) {
	if d.ipStore == nil {
		return false, 0 // Graceful degradation
	}

	// Check if store is healthy
	health := d.ipStore.GetHealth()
	if health.Status != datastores.HealthHealthy {
		return false, 0
	}

	// In a real implementation, we'd use type-safe methods
	// For testing, we'll access the underlying mock store
	store, ok := d.ipStore.(*testIPReputationStore)
	if !ok {
		return false, 0
	}

	rep, found := store.Read(ip)
	if !found {
		return false, 0
	}

	return true, rep.Severity
}

func (d *networkAnalyzerDetector) ListThreatSources() []string {
	if d.ipStore == nil {
		return []string{}
	}

	store, ok := d.ipStore.(*testIPReputationStore)
	if !ok {
		return []string{}
	}

	return store.ListSourcesHelper()
}

// testIPReputationStore is a minimal mock store for testing detector communication
type testIPReputationStore struct {
	data map[string]map[string]*testIPRep // [source][ip]
	mu   sync.RWMutex
}

type testIPRep struct {
	Severity int
	Tags     []string
}

func newTestIPReputationStore() *testIPReputationStore {
	return &testIPReputationStore{
		data: make(map[string]map[string]*testIPRep),
	}
}

func (s *testIPReputationStore) Name() string {
	return "ip_reputation"
}

func (s *testIPReputationStore) GetHealth() *datastores.HealthInfo {
	return &datastores.HealthInfo{
		Status:    datastores.HealthHealthy,
		Message:   "",
		LastCheck: time.Now(),
	}
}

func (s *testIPReputationStore) GetMetrics() *datastores.DataStoreMetrics {
	s.mu.RLock()
	defer s.mu.RUnlock()

	count := int64(0)
	for _, source := range s.data {
		count += int64(len(source))
	}

	return &datastores.DataStoreMetrics{
		ItemCount:  count,
		LastAccess: time.Now(),
	}
}

func (s *testIPReputationStore) WriteValue(source string, entry *datastores.DataEntry) error {
	return nil // Simplified for testing
}

func (s *testIPReputationStore) WriteBatchValues(source string, entries []*datastores.DataEntry) error {
	return nil // Simplified for testing
}

func (s *testIPReputationStore) Delete(source string, key *anypb.Any) error {
	return nil // Simplified for testing
}

func (s *testIPReputationStore) ClearSource(source string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.data, source)
	return nil
}

func (s *testIPReputationStore) ListSources() ([]string, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	sources := make([]string, 0, len(s.data))
	for source := range s.data {
		sources = append(sources, source)
	}
	return sources, nil
}

// Test-specific helper methods
func (s *testIPReputationStore) Write(source, ip string, severity int, tags []string) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.data[source] == nil {
		s.data[source] = make(map[string]*testIPRep)
	}

	s.data[source][ip] = &testIPRep{
		Severity: severity,
		Tags:     tags,
	}
}

func (s *testIPReputationStore) Read(ip string) (*testIPRep, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	// Merge all sources (simplified conflict resolution - first found wins)
	for _, source := range s.data {
		if rep, ok := source[ip]; ok {
			return rep, true
		}
	}

	return nil, false
}

func (s *testIPReputationStore) ListSourcesHelper() []string {
	s.mu.RLock()
	defer s.mu.RUnlock()

	sources := make([]string, 0, len(s.data))
	for source := range s.data {
		sources = append(sources, source)
	}
	return sources
}

// mockLogger implements detection.Logger for testing
type mockLogger struct{}

func (m *mockLogger) Debugw(msg string, keysAndValues ...interface{})    {}
func (m *mockLogger) Infow(msg string, keysAndValues ...interface{})     {}
func (m *mockLogger) Warnw(msg string, keysAndValues ...interface{})     {}
func (m *mockLogger) Errorw(msg string, keysAndValues ...interface{})    {}
func (m *mockLogger) With(keysAndValues ...interface{}) detection.Logger { return m }

// Helper function to parse comma-separated tag strings
func parseTagString(tags string) []string {
	if tags == "" {
		return []string{}
	}
	result := []string{}
	for _, tag := range splitString(tags, ",") {
		if trimmed := trimSpace(tag); trimmed != "" {
			result = append(result, trimmed)
		}
	}
	return result
}

func splitString(s, sep string) []string {
	if s == "" {
		return []string{}
	}
	result := []string{}
	current := ""
	for i := 0; i < len(s); i++ {
		if i+len(sep) <= len(s) && s[i:i+len(sep)] == sep {
			result = append(result, current)
			current = ""
			i += len(sep) - 1
		} else {
			current += string(s[i])
		}
	}
	if current != "" || len(result) == 0 {
		result = append(result, current)
	}
	return result
}

func trimSpace(s string) string {
	start := 0
	end := len(s)
	for start < end && (s[start] == ' ' || s[start] == '\t' || s[start] == '\n' || s[start] == '\r') {
		start++
	}
	for end > start && (s[end-1] == ' ' || s[end-1] == '\t' || s[end-1] == '\n' || s[end-1] == '\r') {
		end--
	}
	return s[start:end]
}
