# Docs

In this section you can find the complete reference documentation for all of the different features and settings that Tracee has to offer.

!!! Note
    We have recently transitioned to a new architecture and user-experience, as detailed [here](https://github.com/aquasecurity/tracee/discussions/2499), and the documentation has been updated accordingly.  

## Why Choose Tracee?

Tracee stands out from other security and observability tools through several key differentiators:

### 🎯 Everything is an Event
Unlike tools that separate raw data from detections, Tracee presents **everything as events** - from low-level system calls to high-level security detections. This unified approach lets you:
- Combine different event types in the same policy
- Build complex detection logic across multiple data sources
- Maintain a consistent view of your system's behavior

### 📊 Rich Event Coverage with Minimal Effort
Tracee provides extensive built-in events out of the box:
- **400+ system calls** for comprehensive system monitoring
- **Network events** including DNS, HTTP, and packet analysis
- **Security events** with pre-built threat detection signatures
- **Container events** with native Kubernetes integration

### 🛠️ Simplicity without Compromise
Create powerful policies with just a few lines of YAML:
- **Intuitive syntax** for scoping and filtering
- **Flexible targeting** from global to container-specific
- **Easy deployment** across development and production environments

### 🔍 Forensic Capabilities
Go beyond detection with artifact collection:
- **Network traffic capture** for detailed analysis
- **Binary collection** for malware investigation
- **Memory dumps** for advanced forensics
- **File artifacts** for compliance and auditing

### 🔗 Unified Architecture
Everything works together seamlessly:
- Events flow through the same processing pipeline
- Policies can reference any combination of event types
- Custom signatures integrate naturally with built-in events
- Single configuration controls the entire system

---

👈 Please use the side-navigation on the left in order to browse the different topics.
