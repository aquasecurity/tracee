package ipreputation

import (
	"time"
)

// ReputationStatus indicates the reputation classification of an IP address
type ReputationStatus int

const (
	ReputationUnknown ReputationStatus = iota
	ReputationWhitelisted
	ReputationBlacklisted
	ReputationSuspicious
)

// String returns the string representation of the reputation status
func (r ReputationStatus) String() string {
	switch r {
	case ReputationWhitelisted:
		return "whitelisted"
	case ReputationBlacklisted:
		return "blacklisted"
	case ReputationSuspicious:
		return "suspicious"
	default:
		return "unknown"
	}
}

// IPReputation represents threat intelligence data for an IP address
type IPReputation struct {
	IP          string
	Status      ReputationStatus
	Source      string // Source that provided this data
	Severity    int    // 1-10 severity score
	Tags        []string
	LastUpdated time.Time
	Metadata    map[string]string
}

// ConflictResolutionPolicy defines how to handle multiple sources writing different data for the same key
type ConflictResolutionPolicy int

const (
	// LastWriteWins - most recent write takes precedence (based on LastUpdated timestamp)
	LastWriteWins ConflictResolutionPolicy = iota
	// MaxSeverity - highest severity value across all sources wins
	MaxSeverity
	// PriorityBased - source with highest priority wins (based on source priority map)
	PriorityBased
)

// String returns the string representation of the conflict resolution policy
func (c ConflictResolutionPolicy) String() string {
	switch c {
	case LastWriteWins:
		return "last_write_wins"
	case MaxSeverity:
		return "max_severity"
	case PriorityBased:
		return "priority_based"
	default:
		return "unknown"
	}
}
