# Detector Documentation

Welcome to Tracee's Detector system documentation. Detectors are the modern way to write custom threat detection and event derivation logic in Tracee.

## What are Detectors?

Detectors analyze runtime events to identify security threats and derive higher-level events from raw eBPF data. They provide:

- **Type-safe APIs**: Direct protobuf access with compile-time guarantees
- **Rich context**: Access to process trees, containers, DNS cache, and more
- **Declarative filtering**: Engine-level event filtering by data, scope, and version
- **Auto-enrichment**: Automatic population of threat metadata and process ancestry
- **Built-in observability**: Prometheus metrics and structured logging

## Documentation

### [Developer Guide](developer-guide.md)

Complete guide to writing detectors, from quick start to advanced features:

- Quick start with a working example
- Detector definition and requirements
- Data access patterns and helpers
- DataStore usage for system state queries
- Auto-population of event fields
- Advanced features (enrichments, architecture filtering, version constraints)
- Lifecycle management (Init, OnEvent, Close)
- Testing strategies
- Migration from old signature API
- Best practices and real examples

**Start here** if you're writing your first detector or migrating from signatures.

### [DataStore API Reference](datastore-api.md)

Complete API reference for all datastores:

- ProcessStore: Process information and ancestry
- ContainerStore: Container and Kubernetes metadata
- SystemStore: Immutable system information
- SyscallStore: Syscall ID/name mapping
- KernelSymbolStore: Kernel symbol resolution
- DNSStore: DNS cache queries
- Health monitoring and metrics
- Error handling patterns

**Reference this** when you need detailed API documentation for specific datastores.

## Quick Links

- **Example Detector**: See `detectors/example_detector.go` for a complete, annotated example
- **Real Detectors**: Browse `detectors/` directory for production implementations
- **API Definitions**: See `api/v1beta1/detection/detector.go` for interface definitions
- **DataStore Interfaces**: See `api/v1beta1/datastores/interfaces.go` for store APIs

## Key Concepts

### EventDetector Interface

All detectors implement this interface:

```go
type EventDetector interface {
    GetDefinition() DetectorDefinition  // What this detector does
    Init(params DetectorParams) error   // Initialize resources
    OnEvent(ctx context.Context, event *v1beta1.Event) ([]*v1beta1.Event, error)
}
```

### Auto-Registration

Detectors automatically register themselves using `init()`:

```go
func init() {
    register(&MyDetector{})
}
```

No manual list maintenance required—just create a file with `init()` and it's registered.

### Requirements and Filtering

Declare what your detector needs:

```go
Requirements: detection.DetectorRequirements{
    Events: []detection.EventRequirement{
        {
            Name: "openat",
            DataFilters: []string{"pathname=/etc/*"},  // Engine filters
            ScopeFilters: []string{"container=started"},
        },
    },
    DataStores: []detection.DataStoreRequirement{
        {Name: "process", Dependency: detection.DependencyRequired},
    },
}
```

### Auto-Population

Declaratively specify field enrichment:

```go
AutoPopulate: detection.AutoPopulateFields{
    Threat:          true,  // Copy threat metadata
    DetectedFrom:    true,  // Provenance tracking
    ProcessAncestry: true,  // 5-level ancestry chain
}
```

## Example: Simple Detector

```go
package detectors

import (
    "context"
    "github.com/aquasecurity/tracee/api/v1beta1"
    "github.com/aquasecurity/tracee/api/v1beta1/detection"
)

func init() {
    register(&SensitiveFileAccess{})
}

type SensitiveFileAccess struct {
    logger detection.Logger
}

func (d *SensitiveFileAccess) GetDefinition() detection.DetectorDefinition {
    return detection.DetectorDefinition{
        ID: "TRC-001",
        Requirements: detection.DetectorRequirements{
            Events: []detection.EventRequirement{
                {
                    Name: "security_file_open",
                    DataFilters: []string{"pathname=/etc/shadow"},
                },
            },
        },
        ProducedEvent: v1beta1.EventDefinition{
            Name:        "sensitive_file_access",
            Description: "Access to sensitive system files",
            Version:     &v1beta1.Version{Major: 1, Minor: 0, Patch: 0},
        },
        ThreatMetadata: &v1beta1.Threat{
            Name:     "Sensitive File Access",
            Severity: v1beta1.Severity_MEDIUM,
        },
        AutoPopulate: detection.AutoPopulateFields{
            Threat:          true,
            DetectedFrom:    true,
            ProcessAncestry: true,
        },
    }
}

func (d *SensitiveFileAccess) Init(params detection.DetectorParams) error {
    d.logger = params.Logger
    return nil
}

func (d *SensitiveFileAccess) OnEvent(ctx context.Context, event *v1beta1.Event) ([]*v1beta1.Event, error) {
    pathname, _ := v1beta1.GetData[string](event, "pathname")

    detection := v1beta1.CreateEventFromBase(event)
    detection.Data = []*v1beta1.EventValue{
        v1beta1.NewStringValue("file", pathname),
    }

    return []*v1beta1.Event{detection}, nil
}
```

## Building and Testing

```bash
# Build Tracee with your detector
make tracee

# Run Tracee with process tree enabled (required for ProcessAncestry)
sudo ./dist/tracee --proctree source=both

# View detections (in another terminal)
sudo ./dist/traceectl stream --format json
```

## Migration from Signatures

Existing signatures can be migrated to the new detector API. The [Developer Guide](developer-guide.md#migration-from-signatures) includes:

- Step-by-step migration instructions
- Pattern translations (old → new)
- Complete before/after examples
- Migration checklist

## Community and Support

- **Tracee GitHub**: https://github.com/aquasecurity/tracee
- **Issues**: Report bugs and request features
- **Discussions**: Ask questions and share detectors
- **Documentation**: https://aquasecurity.github.io/tracee/

---

**Ready to start?** Jump to the [Developer Guide](developer-guide.md) for a complete walkthrough.

