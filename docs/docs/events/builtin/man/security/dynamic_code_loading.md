---
title: TRACEE-DYNAMIC-CODE-LOADING
section: 1
header: Tracee Event Manual
---

## NAME

**dynamic_code_loading** - detect dynamic code loading through memory protection changes

## DESCRIPTION

This event detects potential dynamic code loading by monitoring changes in memory protection attributes. It specifically identifies when a memory region transitions from being writable to executable, which often indicates that code has been written to memory and is about to be executed.

Dynamic code loading can be used legitimately (e.g., JIT compilation) but is also a common technique used by malware to execute code without writing files to disk, making it harder to detect through static analysis.

## SIGNATURE METADATA

- **ID**: TRC-104
- **Version**: 1
- **Severity**: 2
- **Category**: defense-evasion
- **Technique**: Software Packing
- **MITRE ID**: attack-pattern--deb98323-e13f-4b0c-8d94-175379069062
- **MITRE External ID**: T1027.002

## EVENT SETS

**signatures**, **default**

## DATA FIELDS

This signature event uses fields from the underlying mem_prot_alert event:

**pathname** (*string*)
: Path to the executable containing the memory region

**prev_prot** (*string*)
: Previous memory protection flags

**prot** (*string*)
: New memory protection flags

**vm_file** (*string*)
: Associated file mapping information

**offset** (*uint64*)
: Offset within the memory region

## DEPENDENCIES

- `mem_prot_alert`: Monitor memory protection changes

## USE CASES

- **Malware detection**: Identify fileless malware execution

- **Runtime integrity**: Monitor for unexpected code execution

- **Security analysis**: Track dynamic code behavior

- **Threat hunting**: Detect evasive malware techniques

## MEMORY PROTECTION

Protection flag transitions:

- **W→X**: Write to Execute (suspicious)
- **W+X**: Simultaneous Write/Execute (highly suspicious)
- **R→X**: Read to Execute (common for JIT)
- **None→X**: No access to Execute (potential unpacking)

## ATTACK VECTORS

Common malicious uses include:

- **Fileless malware**: Execute code without files
- **Shellcode injection**: Dynamic code execution
- **Packer unpacking**: Runtime code decryption
- **Memory-resident malware**: Avoid disk artifacts

## RISK ASSESSMENT

Risk factors to consider:

- **Evasion Technique**: Bypasses static analysis
- **Fileless Attack**: No filesystem artifacts
- **Memory Analysis**: Required for detection
- **False Positives**: Common in JIT environments

## LEGITIMATE USES

Valid dynamic code scenarios:

- JIT compilation
- Runtime code generation
- Plugin systems
- Dynamic language interpreters

## RELATED EVENTS

- **mem_prot_alert**: Memory protection changes
- **security_file_mprotect**: Memory protection syscalls
- **process_vm_write**: Process memory modifications
- **shared_object_loaded**: Dynamic library loading
