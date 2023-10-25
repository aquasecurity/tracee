
# Dynamic Code Loading Detection

## Intro

The `DynamicCodeLoading` signature identifies potential threats associated with
dynamic code loading. Dynamic code loading is a technique that can be used by
attackers to introduce and execute malicious code at runtime, bypassing static
analysis mechanisms.

## Description

Certain defensive tools monitor the attributes of memory regions in binaries to
detect misconduct. If a memory region switches from being "writable" to
"executable", it may indicate that code was written to it and is now intended to
be run - a potential sign of dynamic code loading.

The `DynamicCodeLoading` signature vigilantly observes these memory protection
alerts to recognize any that signify a transition from "W" (Writable) to "E"
(Executable). This could signify an attempt to load code dynamically for
possible malicious intent, bypassing some detection mechanisms.

## Purpose

The primary goal of the `DynamicCodeLoading` signature is to provide
instantaneous detection and alerts when a binary's memory protection attributes
change in a manner indicative of dynamic code loading.

Detecting this behavior is essential as it can be used by adversaries to execute
malicious code covertly without actually having to drop executable files onto
the file system.

## Metadata

- **ID**: TRC-104
- **Version**: 1
- **Name**: Dynamic code loading detected
- **EventName**: dynamic_code_loading
- **Description**: Highlights potential dynamic code loading attempts characterized by the binary's memory being both writable and executable. This method can be adopted by adversaries to execute malicious instructions stealthily without storing executable files on the system.
- **Properties**:
  - **Severity**: 2 (Moderate threat level)
  - **Category**: defense-evasion
  - **Technique**: Software Packing
  - **Kubernetes_Technique**: N/A
  - **id**: attack-pattern--deb98323-e13f-4b0c-8d94-175379069062
  - **external_id**: T1027.002

## Findings

Upon the detection of a potential dynamic code loading instance:

- **SigMetadata**: Renders a comprehensive threat profile as outlined by the signature's definitions.
- **Event**: Chronicles a thorough log of the particular event that led to the alert.
- **Data**: Presently flagged as `nil`, indicating that no supplementary data is associated with the detection.

## Events Used

This signature is particularly interested in:

- `mem_prot_alert`: Fired whenever there's an alert about memory protection
attributes in a binary. The signature specifically looks for alerts indicating a
protection change from "W" (Writable) to "E" (Executable) - a potential hint at
dynamic code loading.
