# Detector Quick Start Guide

Get your first Tracee detector running in 30 minutes. This hands-on tutorial assumes basic Go knowledge but no prior Tracee experience.

## What You'll Build

A detector that identifies when processes access sensitive system files like `/etc/shadow` or `/etc/sudoers`, with:

- Automatic threat metadata enrichment
- Full process ancestry (parent → grandparent → ...)
- Container context (if applicable)

## Prerequisites

```bash
# Clone Tracee
git clone https://github.com/aquasecurity/tracee
cd tracee

# Verify build environment
make env

# Required: Linux kernel 4.18+, Go 1.24+, Clang 12+
```

## Step 1: Create Your Detector File

Create `detectors/sensitive_file_access.go`:

{% raw %}
```go
package detectors

import (
	"context"

	"github.com/aquasecurity/tracee/api/v1beta1"
	"github.com/aquasecurity/tracee/api/v1beta1/detection"
)

// Auto-register the detector on startup
func init() {
	register(&SensitiveFileAccess{})
}

// SensitiveFileAccess detects access to sensitive system files
type SensitiveFileAccess struct {
	logger detection.Logger
}

// GetDefinition declares what this detector does and what it needs
func (d *SensitiveFileAccess) GetDefinition() detection.DetectorDefinition {
	return detection.DetectorDefinition{
		ID: "TRC-001",  // Unique identifier
		
		Requirements: detection.DetectorRequirements{
			Events: []detection.EventRequirement{
				{
					Name: "security_file_open",
					// Engine filters - only matching events reach OnEvent()
					DataFilters: []string{
						"pathname=/etc/shadow",
						"pathname=/etc/sudoers",
					},
				},
			},
		},
		
		// Define the output event this detector produces
		ProducedEvent: v1beta1.EventDefinition{
			Name:        "sensitive_file_access",
			Description: "Access to sensitive system files detected",
			Version: &v1beta1.Version{Major: 1, Minor: 0, Patch: 0},
			Fields: []*v1beta1.EventField{
				{Name: "file_path", Type: "const char*"},
				{Name: "executable", Type: "const char*"},
			},
		},
		
		// Threat information template (auto-copied to outputs)
		ThreatMetadata: &v1beta1.Threat{
			Name:        "Sensitive File Access",
			Description: "A process attempted to access a sensitive system file",
			Severity:    v1beta1.Severity_MEDIUM,
		},
		
		// Tell engine to auto-enrich our outputs
		AutoPopulate: detection.AutoPopulateFields{
			Threat:          true,  // Copy ThreatMetadata above
			DetectedFrom:    true,  // Link to triggering event
			ProcessAncestry: true,  // Add 5 levels of parent processes
		},
	}
}

// Init is called once at startup
func (d *SensitiveFileAccess) Init(params detection.DetectorParams) error {
	d.logger = params.Logger
	d.logger.Infow("SensitiveFileAccess detector initialized")
	return nil
}

// OnEvent processes each matching event
func (d *SensitiveFileAccess) OnEvent(
	ctx context.Context,
	event *v1beta1.Event,
) ([]detection.DetectorOutput, error) {
	// Type-safe data extraction
	pathname, found := v1beta1.GetData[string](event, "pathname")
	if !found {
		return nil, nil  // Skip if pathname missing
	}

	// Extract executable path (nil-safe protobuf getters)
	executablePath := event.GetWorkload().GetProcess().GetExecutable().GetPath()

	// Return output data - engine handles the rest (threat, ancestry, etc.)
	return []detection.DetectorOutput{{
		Data: []*v1beta1.EventValue{
			v1beta1.NewStringValue("file_path", pathname),
			v1beta1.NewStringValue("executable", executablePath),
		},
	}}, nil
}
```
{% endraw %}

## Step 2: Build Tracee

```bash
# Build with your detector included
make tracee

# The detector is compiled in - no plugins or manual registration needed!
```

## Step 3: Run Tracee

```bash
# Start Tracee with process tree and JSON output
sudo ./dist/tracee --stores process.source=both --output json | jq
```

## Step 4: Trigger Your Detector

In a third terminal, access a sensitive file:

```bash
sudo cat /etc/shadow
```

## Step 5: See the Detection

You should see output like:

```json
{
  "id": 5001,
  "name": "sensitive_file_access",
  "version": "1.0.0",
  "timestamp": "2025-12-16T10:30:45.123Z",
  "threat": {
    "name": "Sensitive File Access",
    "description": "A process attempted to access a sensitive system file",
    "severity": "MEDIUM"
  },
  "data": {
    "file_path": "/etc/shadow",
    "executable": "/bin/cat"
  },
  "detected_from": {
    "event_id": 257,
    "event_name": "security_file_open"
  },
  "workload": {
    "process": {
      "entity_id": 12345,
      "pid": 67890,
      "executable": {"path": "/bin/cat"},
      "ancestors": [
        {"entity_id": 12344, "pid": 67889, "executable": {"path": "/bin/bash"}},
        {"entity_id": 12343, "pid": 67888, "thread": {"name": "sshd"}},
        {"entity_id": 1, "pid": 1, "thread": {"name": "systemd"}}
      ]
    }
  }
}
```

## What Just Happened?

Let's break down the magic:

### 1. Auto-Registration

{% raw %}
```go
func init() {
	register(&SensitiveFileAccess{})
}
```
{% endraw %}

Your detector registered itself automatically. No manual list maintenance!

### 2. Engine Filtering

{% raw %}
```go
DataFilters: []string{
	"pathname=/etc/shadow",
	"pathname=/etc/sudoers",
},
```
{% endraw %}

Tracee's engine filtered millions of `security_file_open` events. Only those matching your paths reached `OnEvent()`. This happens in the engine - super efficient!

### 3. Type-Safe Extraction

{% raw %}
```go
pathname, found := v1beta1.GetData[string](event, "pathname")
```
{% endraw %}

Generic type parameter ensures compile-time type safety. No runtime casting errors!

### 4. Auto-Enrichment

{% raw %}
```go
AutoPopulate: detection.AutoPopulateFields{
	Threat:          true,
	DetectedFrom:    true,
	ProcessAncestry: true,
}
```
{% endraw %}

The engine automatically:

- ✅ Copied `ThreatMetadata` to `output.Threat`
- ✅ Set `output.DetectedFrom` pointing to the triggering event
- ✅ Queried the process tree and populated 5 ancestor levels
- ✅ Preserved timestamp, workload, and policies from input event

You just returned simple data fields - the engine did the heavy lifting!

## Common Patterns

### Multiple Outputs

A single input can produce multiple detections:

{% raw %}
```go
func (d *MyDetector) OnEvent(ctx context.Context, event *v1beta1.Event) ([]detection.DetectorOutput, error) {
	var outputs []detection.DetectorOutput
	
	// Check condition 1
	if isSuspicious {
		outputs = append(outputs, detection.DetectorOutput{
			Data: []*v1beta1.EventValue{
				v1beta1.NewStringValue("reason", "suspicious pattern"),
			},
		})
	}
	
	// Check condition 2
	if isMalicious {
		outputs = append(outputs, detection.DetectorOutput{
			Data: []*v1beta1.EventValue{
				v1beta1.NewStringValue("reason", "known malware signature"),
			},
		})
	}
	
	return outputs, nil
}
```
{% endraw %}

### Custom Threat Severity

Override the default threat metadata per detection:

{% raw %}
```go
return []detection.DetectorOutput{{
	Data: []*v1beta1.EventValue{
		v1beta1.NewStringValue("file", pathname),
	},
	Threat: &v1beta1.Threat{
		Name:        "Critical System File Access",
		Severity:    v1beta1.Severity_CRITICAL,  // Override default MEDIUM
		Description: "Root accessed critical system file",
	},
}}, nil
```
{% endraw %}

### Using DataStores

Access system state like process information:

{% raw %}
```go
func (d *MyDetector) OnEvent(ctx context.Context, event *v1beta1.Event) ([]detection.DetectorOutput, error) {
	entityId := event.GetWorkload().GetProcess().GetEntityId()
	
	// Query process store for process details
	proc, err := d.dataStores.Processes().GetProcess(entityId)
	if errors.Is(err, datastores.ErrNotFound) {
		// Process not in tree yet
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	
	// Use process info in detection logic
	if proc.GetInterpreter().GetPath() == "/bin/bash" {
		return []detection.DetectorOutput{{
			Data: []*v1beta1.EventValue{
				v1beta1.NewStringValue("shell", "bash"),
			},
		}}, nil
	}
	
	return nil, nil
}
```
{% endraw %}

### Filtering by Container

Only detect events from containers:

{% raw %}
```go
Requirements: detection.DetectorRequirements{
	Events: []detection.EventRequirement{
		{
			Name: "security_file_open",
			ScopeFilters: []string{"container=started"},  // Containers only
		},
	},
}
```
{% endraw %}

Or only from host:

{% raw %}
```go
ScopeFilters: []string{"not-container"},  // Host only
```
{% endraw %}

## Debugging Tips

### Enable Debug Logging

```bash
# Run with debug logs
sudo ./dist/tracee --logging debug --stores process.source=both
```

### Check Detector Registration

```bash
# List detector events
sudo ./dist/tracee list | grep detectors
```

### Verify Event Filtering

Check that your event name is correct:

```bash
# List available events
sudo ./dist/tracee list | grep security_file_open
```

### Test Without Filters

Temporarily remove `DataFilters` to see all events:

{% raw %}
```go
Requirements: detection.DetectorRequirements{
	Events: []detection.EventRequirement{
		{
			Name: "security_file_open",
			// DataFilters: []string{...},  // Commented out for testing
		},
	},
}
```
{% endraw %}

Add logging in `OnEvent()`:

{% raw %}
```go
func (d *SensitiveFileAccess) OnEvent(ctx context.Context, event *v1beta1.Event) ([]detection.DetectorOutput, error) {
	d.logger.Debugw("Event received", "event", event.Name)
	// ... rest of logic
}
```
{% endraw %}

## Next Steps

Congratulations! You've written your first Tracee detector. Now explore:

### 📚 Deep Dive into APIs
- **[API Reference](api-reference.md)**: Complete detector API documentation
- **[DataStore API](datastore-api.md)**: Query process trees, containers, DNS, and more

### 🔄 Migration and Troubleshooting
- **[Migration Guide](api-reference.md#migration-from-signatures)**: Migrating from old signatures
- **[Troubleshooting](api-reference.md#troubleshooting)**: Common issues and solutions

### 🔍 Study Real Examples
- Browse `detectors/` directory for production implementations
- See `api/v1beta1/detection/detector.go` for interface definitions

### 🧪 Write Tests
- Add unit tests in `detectors/sensitive_file_access_test.go`
- See [Testing Guide](api-reference.md#testing) for patterns

## Troubleshooting

### Detector Not Running

**Problem**: Your detector code changed but behavior didn't

**Solution**: Rebuild Tracee - detectors are compiled in, not dynamically loaded
```bash
make tracee
```

### No Events Received

**Problem**: `OnEvent()` never called

**Possible causes**:

1. Wrong event name - check `tracee list`
2. Filters too restrictive - temporarily remove them
3. Event not enabled - Tracee enables events based on requirements automatically

### Process Ancestry Empty

**Problem**: `workload.process.ancestors` is null

**Solution**: Enable process tree:
```bash
sudo ./dist/tracee --stores process.source=both
```

### Build Errors

**Problem**: Compilation fails

**Common fixes**:
```bash
# Update dependencies
make go-tidy

# Clean build
make clean
make tracee
```

## Quick Reference

### Detector Skeleton

{% raw %}
```go
package detectors

import (
	"context"

	"github.com/aquasecurity/tracee/api/v1beta1"
	"github.com/aquasecurity/tracee/api/v1beta1/datastores"
	"github.com/aquasecurity/tracee/api/v1beta1/detection"
)

func init() {
	register(&MyDetector{})
}

type MyDetector struct {
	logger     detection.Logger
	dataStores datastores.Registry
}

func (d *MyDetector) GetDefinition() detection.DetectorDefinition {
	return detection.DetectorDefinition{
		ID: "TRC-XXX",
		Requirements: detection.DetectorRequirements{
			Events: []detection.EventRequirement{{Name: "event_name"}},
		},
		ProducedEvent: v1beta1.EventDefinition{
			Name:    "my_detection",
			Version: &v1beta1.Version{Major: 1},
		},
		AutoPopulate: detection.AutoPopulateFields{
			Threat:          true,
			DetectedFrom:    true,
			ProcessAncestry: true,
		},
	}
}

func (d *MyDetector) Init(params detection.DetectorParams) error {
	d.logger = params.Logger
	d.dataStores = params.DataStores
	return nil
}

func (d *MyDetector) OnEvent(ctx context.Context, event *v1beta1.Event) ([]detection.DetectorOutput, error) {
	// Your detection logic
	return []detection.DetectorOutput{{
		Data: []*v1beta1.EventValue{},
	}}, nil
}
```
{% endraw %}

### Essential Commands

```bash
# Build
make tracee

# Run with process tree
sudo ./dist/tracee --stores process.source=both

# View detections in JSON
sudo ./dist/tracee --output json | jq

# List detector events
sudo ./dist/tracee list | grep detectors

# Debug mode
sudo ./dist/tracee --logging debug
```

---

**Ready for more?** Continue to the [API Reference](api-reference.md) for comprehensive documentation, including migration guides and troubleshooting.

