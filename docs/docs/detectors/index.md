# Detector Documentation

Detectors are the modern way to write custom threat detection and event derivation logic in Tracee.

## What are Detectors?

Detectors analyze runtime events to identify security threats and derive higher-level events from raw eBPF data. They provide:

- **Type-safe APIs**: Direct protobuf access with compile-time guarantees
- **Rich context**: Access to process trees, containers, DNS cache, and more
- **Declarative filtering**: Engine-level event filtering by data, scope, and version
- **Auto-enrichment**: Automatic population of threat metadata and process ancestry
- **Built-in observability**: Prometheus metrics and structured logging

## Documentation Guide

### 🚀 For Newcomers

**Start here if you're new to Tracee detectors:**

#### [Quick Start Guide](quickstart.md)
**Get your first detector running in 30 minutes**

Step-by-step tutorial to build a working detector:

- Create a detector file
- Build and run Tracee
- Trigger and observe detections
- Understand auto-registration, filtering, and enrichment

Perfect for: First-time detector developers, hands-on learners

---

### 📚 For Reference

**Comprehensive API documentation:**

#### [Detector API Reference](api-reference.md)
**Complete detector API specification**

Everything you need to know about the detector API:

- Core interfaces and structures
- Event requirements and filtering
- Auto-population features
- Advanced features and lifecycle management
- Testing patterns and best practices
- Migration from old signatures
- Troubleshooting common issues

Perfect for: Understanding all capabilities, deep dives, migrating from signatures

#### [DataStore API Reference](datastore-api.md)
**Complete datastore API specification**

Query system state from your detectors:

- ProcessStore (process information and ancestry)
- ContainerStore (container and Kubernetes metadata)
- SystemStore, SyscallStore, KernelSymbolStore, DNSStore
- Health monitoring and error handling

Perfect for: Detectors that need to query system state and context

---

## Quick Example

Here's a minimal detector to give you a taste:

{% raw %}
```go
package detectors

import (
    "context"
    "github.com/aquasecurity/tracee/api/v1beta1"
    "github.com/aquasecurity/tracee/api/v1beta1/detection"
)

func init() {
    register(&SensitiveFileAccess{})  // Auto-register
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
                    DataFilters: []string{"pathname=/etc/shadow"},  // Engine filters
                },
            },
        },
        ProducedEvent: v1beta1.EventDefinition{
            Name:    "sensitive_file_access",
            Version: &v1beta1.Version{Major: 1},
        },
        ThreatMetadata: &v1beta1.Threat{
            Severity: v1beta1.Severity_HIGH,
        },
        AutoPopulate: detection.AutoPopulateFields{
            Threat:          true,  // Auto-copy threat metadata
            ProcessAncestry: true,  // Auto-fetch process tree
        },
    }
}

func (d *SensitiveFileAccess) Init(params detection.DetectorParams) error {
    d.logger = params.Logger
    return nil
}

func (d *SensitiveFileAccess) OnEvent(ctx context.Context, event *v1beta1.Event) ([]detection.DetectorOutput, error) {
    pathname, _ := v1beta1.GetData[string](event, "pathname")
    return []detection.DetectorOutput{{
        Data: []*v1beta1.EventValue{
            v1beta1.NewStringValue("file", pathname),
        },
    }}, nil
}
```
{% endraw %}

**See the [Quick Start Guide](quickstart.md) for a complete walkthrough.**

## Documentation at a Glance

| Document | Purpose | Audience |
|----------|---------|----------|
| [Quick Start](quickstart.md) | Hands-on tutorial, first detector | Newcomers |
| [API Reference](api-reference.md) | Complete detector API + migration + troubleshooting | All developers |
| [DataStore API](datastore-api.md) | Complete datastore API docs | Developers using datastores |

**Total reading time to first detector**: ~30 minutes (Quick Start only)

## Resources

### Code Examples
- **Quick Start Example**: [Quick Start Guide](quickstart.md) - complete annotated walkthrough
- **Comprehensive Example**: `detectors/example_detector.go` - demonstrates all detector API features including DataStore usage, filtering patterns, and enrichment (build with `make tracee-with-examples`)
- **Real Detectors**: Browse `detectors/` directory for production implementations
- **Migration Examples**: [API Reference](api-reference.md#migration-from-signatures) - signature → detector

### API Definitions
- **Detector Interfaces**: `api/v1beta1/detection/detector.go`
- **DataStore Interfaces**: `api/v1beta1/datastores/interfaces.go`
- **Event Protobuf**: `api/v1beta1/event.proto`

### Migration from Signatures
Existing signatures can be migrated to the new detector API. See [Migration Guide](api-reference.md#migration-from-signatures) for:

- Side-by-side API comparison
- Step-by-step migration instructions
- Pattern translations and examples
- Complete migration checklist

## Community and Support

- **Tracee GitHub**: https://github.com/aquasecurity/tracee
- **Issues**: Report bugs and request features
- **Discussions**: Ask questions and share detectors
- **Documentation**: https://aquasecurity.github.io/tracee/

---

**Ready to start?** Jump to the [Quick Start Guide](quickstart.md) for a hands-on tutorial, or dive into the [API Reference](api-reference.md) for complete documentation.
