---
title: TRACEE-HIDDEN-FILE-CREATED
section: 1
header: Tracee Event Manual
---

## NAME

**hidden_file_created** - detect creation of hidden executable files

## DESCRIPTION

This event detects attempts to create hidden executable files (ELF format) in the system. In Unix-like systems, files and directories starting with a dot (.) are hidden from standard directory listings. While this convention is commonly used for configuration files, it can be exploited by attackers to conceal malicious executables.

The event combines path analysis (looking for "/.") with magic byte checking to identify hidden ELF files being created, providing early warning of potential malicious activity attempting to operate stealthily on the system.

## SIGNATURE METADATA

- **ID**: TRC-1015
- **Version**: 1
- **Severity**: 2
- **Category**: defense-evasion
- **Technique**: Hidden Files and Directories
- **MITRE ID**: attack-pattern--ec8fc7e2-b356-455c-8db5-2e37be158e7d
- **MITRE External ID**: T1564.001

## EVENT SETS

**signatures**, **default**

## DATA FIELDS

This signature event uses fields from the underlying magic_write event:

**pathname** (*string*)
: Path to the file being created

**bytes** (*[]byte*)
: Magic bytes written to the file

**source** (*string*)
: Process or context creating the file

## DEPENDENCIES

- `magic_write`: Monitor file content magic bytes

## USE CASES

- **Malware detection**: Identify hidden malicious executables

- **Defense evasion detection**: Spot attempts to hide malicious tools

- **System integrity**: Monitor for unauthorized hidden binaries

- **Incident response**: Track creation of suspicious executables

## HIDDEN FILE PATTERNS

Common hiding techniques:

- **Dot files**: Starting with "."
- **Dot directories**: Hidden within "." directories
- **Multiple dots**: Using ".." or "..."
- **Unicode tricks**: Using special characters
- **Nested hiding**: Hidden files in hidden directories

## ATTACK VECTORS

Common malicious uses include:

- **Malware persistence**: Hiding malicious programs
- **Tool concealment**: Masking attacker tools
- **Backdoor placement**: Hiding unauthorized access methods
- **Data exfiltration**: Concealing collection scripts

## RISK ASSESSMENT

Risk factors to consider:

- **Stealth Capability**: Hidden from normal ls commands
- **Execution Rights**: Binary can be run directly
- **System Access**: Full program capabilities
- **Detection Evasion**: May bypass security scans

## LEGITIMATE USES

Valid hidden executable scenarios:

- Development tools and scripts
- User-specific binaries
- Application plugins
- Package manager internals

## MITIGATION

Recommended security controls:

- Regular hidden file audits
- File integrity monitoring
- Execute permission controls
- Hidden file logging

## RELATED EVENTS

- **magic_write**: File content monitoring
- **security_file_open**: File access tracking
- **process_execute**: Executable file execution
- **dropped_executable**: New executable detection
