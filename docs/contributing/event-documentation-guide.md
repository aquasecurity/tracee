# Event Documentation Guide

This guide provides the standard format and requirements for documenting Tracee events in the official documentation. Following these standards ensures consistency and quality across all event documentation.

> **Note**: This guide complements the [Adding New Events](adding-events.md) guide. Complete the technical implementation first, then use this guide for creating proper documentation.

## Why Documentation Standards Matter

Consistent event documentation helps users:

- **Understand event purpose** and when to use specific events
- **Configure events correctly** with accurate field names and types
- **Troubleshoot issues** with clear dependency information
- **Discover related events** for comprehensive monitoring

## Required Sections

Every event documentation MUST include these sections in this exact order:

### 1. **YAML Frontmatter**
```yaml
---
title: TRACEE-EVENT-NAME
section: 1
header: Tracee Event Manual
---
```

### 2. **NAME**
- Format: `**event_name** - brief one-line description`
- Keep description concise and accurate

### 3. **DESCRIPTION**
- First paragraph: When the event is triggered and what it captures
- Second paragraph: Additional context about the event's purpose and importance
- Keep descriptions focused on **what/when/how** rather than **why** (save for USE CASES)
- Avoid excessive technical jargon

### 4. **EVENT SETS**
- List the event sets this event belongs to (from `pkg/events/core.go`)
- Use **none** if the event doesn't belong to any sets
- Example: `**proc**, **proc_life**` or `**none**`

### 5. **DATA FIELDS**
- List ALL data fields exactly as defined in `pkg/events/core.go`
- Format: `**field_name** (*type*)`
- Follow with `: Description of the field`
- Types must match exactly (e.g., `int32`, `uint64`, `string`, `time.Time`, `SockAddr`)
- Field names must match exactly from the source code
- If no fields: "This event currently does not capture specific arguments, but provides timing and context information about when [description]."

### 6. **DEPENDENCIES**
- **CRITICAL**: Extract probe information from `pkg/ebpf/probes/probe_group.go`
- Use kernel function names/tracepoint names, NOT internal Tracee probe handles
- Format headers:
  - `**Kernel Probe:**` (singular) for kprobes
  - `**Kernel Tracepoint:**` (singular) for raw tracepoints
- Format entries: `- kernel_function_name (required): Description` for single probes
- **Combine kprobe+kretprobe**: When both entry and return probes exist for the same function, combine as:
  - `- function_name (kprobe + kretprobe, required): Description`
- For combined probes, include the probe types to clarify the instrumentation method
- For multiple dependencies, list each type separately
- Include tail calls if present: `**Tail Calls:** - call_name: Description`

### 7. **USE CASES**
- Provide 3-5 specific, actionable use cases
- Format: `- **Category**: Specific use case description`
- Focus on practical applications for users
- Be specific and practical rather than generic

### 8. **RELATED EVENTS**
- List 3-6 related events that users might find relevant
- Format: `- **event_name**: Brief description`
- Include complementary events, lifecycle events, and related security events

## Signature Events Additional Requirements

Signature events require these additional sections:

### **SIGNATURE METADATA** (after DESCRIPTION, before EVENT SETS)
```markdown
- **ID**: TRC-XXX (unique signature identifier)
- **Version**: 1 (signature version number)
- **Severity**: X (threat level number + description)
- **Category**: category-name (e.g., defense-evasion, privilege-escalation)
- **Technique**: Descriptive technique name
- **MITRE ATT&CK**: TXXXX (MITRE ATT&CK technique ID)
- **Tags**: comma-separated tags (optional, e.g., linux, container)
```

### **DETECTION LOGIC** (after USE CASES, before RELATED EVENTS)
- Explain how the signature detection works
- List what the signature monitors for (numbered list preferred)
- Include detection criteria and logic flow
- Format example:
```
The signature monitors for:

1. **Event type** - specific condition or behavior
2. **Analysis step** - how events are processed
3. **Context evaluation** - reducing false positives
```

## Event Type Identification

Before documenting, determine if the event is a **regular event** or a **signature event**:

- **Regular events**: Core system events (syscalls, kernel events, LSM hooks, network events)
- **Signature events**: Security detection rules (found in `docs/events/builtin/man/security/`)

Signature events require additional sections (SIGNATURE METADATA, DETECTION LOGIC) as detailed above.

## Data Accuracy Requirements

### Event Definition Source
- **PRIMARY SOURCE**: `pkg/events/core.go`
- Find the event struct by searching for the event name
- Extract the following with 100% accuracy:

  - `sets: []string{}` → EVENT SETS section
  - `fields: []DataField{}` → DATA FIELDS section (names and types)
  - `dependencies.probes` → DEPENDENCIES section

### Probe Definition Source
- **PRIMARY SOURCE**: `pkg/ebpf/probes/probe_group.go`
- Map internal probe handles to actual kernel attachment points
- Examples:

  - `SysEnter: NewTraceProbe(RawTracepoint, "raw_syscalls:sys_enter", ...)` → `raw_syscalls:sys_enter`
  - `DoExit: NewTraceProbe(KProbe, "do_exit", ...)` → `do_exit`
  - `SecurityFileOpen: NewTraceProbe(KProbe, "security_file_open", ...)` → `security_file_open`

### Probe Type Mapping

- `KProbe` → Use `**Kernel Probe:**` header
- `RawTracepoint` → Use `**Kernel Tracepoint:**` header
- Multiple types → Use separate headers for each type

## Quality Improvements

### Avoid Redundancy

- **Problem**: Having "This event is useful for:" bullets in DESCRIPTION AND a separate USE CASES section creates redundancy
- **Solution**: Keep DESCRIPTION focused on **what/when/how** the event works, save **why/for what** explanations for USE CASES section

### Simplify Dependencies

- **Problem**: Separate entries for kprobe + kretprobe on same function is verbose
- **Solution**: Combine as `function_name (kprobe + kretprobe, required): Description`
- **Example**: Instead of:

  ```
  - vfs_write (required): VFS write function entry
  - vfs_write (required): VFS write function return
  ```
  Use: `- vfs_write (kprobe + kretprobe, required): VFS write function`

## Content Guidelines

### Writing Style

- Use clear, technical language appropriate for system administrators and security professionals
- Avoid marketing language or excessive enthusiasm
- Keep descriptions factual and implementation-focused
- Use present tense for event triggers ("Triggered when...")
- Keep documentation **concise** - aim for 50-70 lines total per event

### Description Structure

1. **Trigger condition**: "Triggered when..."
2. **Context and purpose**: What the event captures and why it's important

### Use Case Categories
Common categories to consider:

- Security monitoring/analysis
- Performance analysis
- Debugging/troubleshooting
- Compliance auditing
- Process/network/file monitoring
- Threat detection/hunting
- Forensic analysis

## Formatting Requirements

### Consistency Rules

- Use `**bold**` for field names, event names, and section emphasis
- Use `*italics*` for data types
- Use `- ` for bullet points (not `* `)
- Use `: ` (colon + space) to separate field names from descriptions
- Use singular headers for dependencies ("Kernel Probe:" not "Kernel Probes:")

### File Naming and Location

- Filename: `event_name.md` (use underscores, lowercase)
- Location based on event category:

  - System events: `docs/docs/events/builtin/man/misc/`
  - LSM events: `docs/docs/events/builtin/man/lsm/`
  - Network events: `docs/docs/events/builtin/man/net/`
  - Container events: `docs/docs/events/builtin/man/containers/`

## Verification Checklist

Before submitting event documentation:

- [ ] All data field names match exactly from `pkg/events/core.go`
- [ ] All data field types match exactly from `pkg/events/core.go`
- [ ] Event sets match exactly from `pkg/events/core.go`
- [ ] Dependencies use kernel function/tracepoint names from `pkg/ebpf/probes/probe_group.go`
- [ ] Probe types correctly mapped to section headers
- [ ] No internal probe handles used in dependencies
- [ ] All required sections present in correct order
- [ ] No prohibited verbose sections included
- [ ] Writing style is clear and technical
- [ ] Use cases are specific and actionable
- [ ] Related events are relevant and helpful

## Example Templates

### Regular Event Template

> **Template Start** - Copy everything between the horizontal lines for regular events

---

```markdown
---
title: TRACEE-EVENT-NAME
section: 1
header: Tracee Event Manual
---

# NAME

**event_name** - brief description

# DESCRIPTION

Triggered when [condition]. This event [captures/provides/monitors] [what].

[Additional context about purpose and implementation].

# EVENT SETS

**set1**, **set2** (or **none**)

# DATA FIELDS

**field_name** (*type*)
: Description of the field

**another_field** (*type*)
: Description of the field

# DEPENDENCIES

**Kernel Probe:**

- kernel_function_name (required): Description

**Kernel Tracepoint:**

- tracepoint:name (required): Description

# USE CASES

- **Security monitoring**: Specific use case

- **Performance analysis**: Specific use case

- **Debugging**: Specific use case

- **Compliance**: Specific use case

- **Monitoring**: Specific use case

# RELATED EVENTS

- **related_event_1**: Brief description
- **related_event_2**: Brief description
- **related_event_3**: Brief description
```

---

> **Template End** - Copy everything above this line

### Signature Event Template

> **Template Start** - Copy everything between the horizontal lines for signature events

---

```markdown
---
title: TRACEE-SIGNATURE-NAME
section: 1
header: Tracee Event Manual
---

# NAME

**signature_name** - brief description of security detection

# DESCRIPTION

Triggered when [security condition]. This security signature [detects/identifies/monitors] [threat/behavior].

[Additional context about threat landscape and detection rationale].

# SIGNATURE METADATA

- **ID**: TRC-XXX
- **Version**: 1
- **Severity**: X (threat level description)
- **Category**: category-name
- **Technique**: Descriptive technique name
- **MITRE ATT&CK**: TXXXX
- **Tags**: tag1, tag2 (optional)

# EVENT SETS

**signatures**, **category_set**

# DATA FIELDS

**field_name** (*type*)
: Description of the field

**detection_context** (*object*)
: Context information about the detection

# DEPENDENCIES

**System Events:**

- base_event (required): System event being analyzed for detection

# USE CASES

- **Threat detection**: Specific threat hunting scenario
- **Security monitoring**: Specific security use case
- **Incident response**: Specific response scenario

# DETECTION LOGIC

The signature monitors for:

1. **Base event** - specific condition or behavior
2. **Analysis criteria** - how events are analyzed
3. **Context evaluation** - reducing false positives

# RELATED EVENTS

- **related_signature**: Brief description
- **base_event**: System event being monitored
- **related_detection**: Similar detection mechanism
```

---

> **Template End** - Copy everything above this line

## Documentation Workflow

### Complete Process

1. **Implement the event** following the [Adding New Events](adding-events.md) guide
2. **Create markdown documentation** following this guide's standards
3. **Verify accuracy** by cross-referencing with `pkg/events/core.go`
4. **Generate man pages** using the specialized build system
5. **Add to navigation** by updating `mkdocs.yml`
6. **Test locally** with MkDocs to ensure proper rendering

### Generating Man Pages

After creating or modifying event documentation, you **must** generate the corresponding man pages:

```bash
# From the Tracee root directory
make -f builder/Makefile.man
```

This command:
- **Builds a Docker container** with pandoc and required tools
- **Converts markdown files** to proper man page format
- **Updates man pages** in the appropriate directories

> **Critical**: Always run this step after creating or modifying event documentation to keep man pages synchronized with markdown files.

---

This guide ensures all Tracee event documentation maintains consistency, accuracy, and usability for users and contributors.
