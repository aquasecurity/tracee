# Detector Documentation

Detectors are the modern way to write custom threat detection and event derivation logic in Tracee.

## What are Detectors?

Detectors analyze runtime events to identify security threats and derive higher-level events from raw eBPF data.

**Two ways to create detectors:**

1. **YAML Detectors**: Declarative configuration - no coding required
2. **Go Detectors**: Full programmatic control with direct API access

Both provide:

- **Declarative filtering**: Engine-level event filtering by data, scope, and version
- **Auto-enrichment**: Automatic population of threat metadata and process ancestry
- **Rich context**: Access to process trees, containers, and more
- **Built-in observability**: Prometheus metrics and structured logging

## Documentation Guide

### 🚀 For Newcomers

**Start here if you're new to Tracee detectors:**

### [YAML Detectors Guide](yaml-detectors.md)

Learn how to create detectors using declarative YAML configuration:

- Quick start with examples
- Complete schema reference
- Event filtering and data extraction
- Threat metadata and auto-population
- Deployment and best practices
- Troubleshooting guide

**Start here** if you want to create detectors without writing Go code.

---

### Go Detectors

Complete guide to writing Go detectors, from quick start to advanced features:

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

## Documentation at a Glance

| Document | Purpose | Audience |
|----------|---------|----------|
| [YAML Detectors](yaml-detectors.md) | Declarative detector creation without code | Security analysts, operators |
| [Quick Start](quickstart.md) | Hands-on tutorial, first Go detector | Go developers |
| [API Reference](api-reference.md) | Complete detector API + migration + troubleshooting | Go developers |
| [DataStore API](datastore-api.md) | Complete datastore API docs | Advanced Go developers |

**Total reading time to first detector**:

- **YAML**: ~15 minutes
- **Go**: ~30 minutes (Quick Start only)

## Resources

### Examples
- **YAML Examples**: `examples/detectors/yaml/` directory - ready-to-use YAML detector examples
- **Go Quick Start**: [Quick Start Guide](quickstart.md) - complete annotated walkthrough
- **Go Comprehensive Example**: `detectors/example_detector.go` - demonstrates all detector API features including DataStore usage, filtering patterns, and enrichment (build with `make tracee-with-examples`)
- **Production Detectors**: Browse `detectors/` directory for real implementations
- **Migration Examples**: [API Reference](api-reference.md#migration-from-signatures) - signature → detector

### API Definitions (Go Detectors)
- **Detector Interfaces**: `api/v1beta1/detection/detector.go`
- **DataStore Interfaces**: `api/v1beta1/datastores/interfaces.go`
- **Event Protobuf**: `api/v1beta1/event.proto`

### YAML Schema
- **Schema Reference**: See [YAML Detectors Guide](yaml-detectors.md) for complete schema
- **Examples**: `examples/detectors/yaml/` directory

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

**Ready to start?**
- **YAML detectors**: Jump to the [YAML Detectors Guide](yaml-detectors.md)
- **Go detectors**: Jump to the [Quick Start Guide](quickstart.md) or dive into the [API Reference](api-reference.md)
