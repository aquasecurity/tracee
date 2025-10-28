package detection

import (
	"fmt"
	"strconv"
)

// DetectorConfig provides type-safe access to detector-specific configuration.
// Detectors should use default values for missing configuration.
type DetectorConfig interface {
	// GetInt retrieves an integer configuration value
	GetInt(key string, defaultValue int) int

	// GetString retrieves a string configuration value
	GetString(key string, defaultValue string) string

	// GetBool retrieves a boolean configuration value
	GetBool(key string, defaultValue bool) bool

	// GetFloat64 retrieves a float64 configuration value
	GetFloat64(key string, defaultValue float64) float64

	// Has checks if a configuration key exists
	Has(key string) bool
}

// detectorConfig implements DetectorConfig with smart type conversion
type detectorConfig struct {
	data map[string]any
}

// NewDetectorConfig creates a new DetectorConfig from a map.
// If data is nil, returns an empty configuration (same as NewEmptyDetectorConfig()).
// For explicit empty config creation, prefer NewEmptyDetectorConfig() for clarity.
func NewDetectorConfig(data map[string]any) DetectorConfig {
	if data == nil {
		return NewEmptyDetectorConfig()
	}
	return &detectorConfig{data: data}
}

// NewEmptyDetectorConfig creates an empty configuration
func NewEmptyDetectorConfig() DetectorConfig {
	return &detectorConfig{data: make(map[string]any)}
}

// GetInt retrieves an integer value with smart type conversion
func (c *detectorConfig) GetInt(key string, defaultValue int) int {
	val, ok := c.data[key]
	if !ok {
		return defaultValue
	}

	// Try direct type assertion first
	switch v := val.(type) {
	case int:
		return v
	case int32:
		return int(v)
	case int64:
		return int(v)
	case uint:
		return int(v)
	case uint32:
		return int(v)
	case uint64:
		return int(v)
	case float32:
		return int(v)
	case float64:
		return int(v)
	case string:
		// Try parsing string as int
		if i, err := strconv.Atoi(v); err == nil {
			return i
		}
	}

	return defaultValue
}

// GetString retrieves a string value with type conversion
func (c *detectorConfig) GetString(key string, defaultValue string) string {
	val, ok := c.data[key]
	if !ok {
		return defaultValue
	}

	// Try direct type assertion first
	if s, ok := val.(string); ok {
		return s
	}

	// Convert other types to string
	return fmt.Sprintf("%v", val)
}

// GetBool retrieves a boolean value with smart type conversion.
func (c *detectorConfig) GetBool(key string, defaultValue bool) bool {
	val, ok := c.data[key]
	if !ok {
		return defaultValue
	}

	// Try direct type assertion first
	if b, ok := val.(bool); ok {
		return b
	}

	// Try parsing as string
	if s, ok := val.(string); ok {
		switch s {
		case "true", "True", "TRUE":
			return true
		case "false", "False", "FALSE":
			return false
		}
	}

	// Try numeric values (0 = false, non-zero = true)
	switch v := val.(type) {
	case int, int32, int64, uint, uint32, uint64:
		return fmt.Sprintf("%v", v) != "0"
	case float32, float64:
		return fmt.Sprintf("%v", v) != "0"
	}

	return defaultValue
}

// GetFloat64 retrieves a float64 value with smart type conversion
func (c *detectorConfig) GetFloat64(key string, defaultValue float64) float64 {
	val, ok := c.data[key]
	if !ok {
		return defaultValue
	}

	// Try direct type assertion first
	switch v := val.(type) {
	case float64:
		return v
	case float32:
		return float64(v)
	case int:
		return float64(v)
	case int32:
		return float64(v)
	case int64:
		return float64(v)
	case uint:
		return float64(v)
	case uint32:
		return float64(v)
	case uint64:
		return float64(v)
	case string:
		// Try parsing string as float
		if f, err := strconv.ParseFloat(v, 64); err == nil {
			return f
		}
	}

	return defaultValue
}

// Has checks if a configuration key exists
func (c *detectorConfig) Has(key string) bool {
	_, ok := c.data[key]
	return ok
}
