---
title: TRACEE-DROPPED-EXECUTABLE
section: 1
header: Tracee Event Manual
---

## NAME

**dropped_executable** - Detection of dropped executables signature

## DESCRIPTION

The **dropped_executable** signature is designed to identify instances where a new executable file is introduced into the system during runtime. This type of activity can often be a significant security concern, especially in containerized environments where images are generally built with all necessary binaries included.

When running containers, a primary security principle is the immutability of container images. This means that once a container image is built, it should have all the binaries and libraries it needs to function. Any deviation from this, such as dropping or introducing new executables during runtime, is often a sign of malicious intent or an indication that the container's integrity has been compromised.

The signature vigilantly monitors for such anomalies. If it detects that a new executable has been introduced into the runtime environment, it triggers an alert.

## SIGNATURE METADATA

- **ID**: TRC-1022
- **Version**: 1
- **Severity**: 2 (Moderate)
- **Category**: defense-evasion
- **Technique**: Masquerading
- **MITRE ATT&CK**: T1036

## EVENT SETS

**signatures**, **security_alert**

## DATA FIELDS

Once an unexpected executable drop is detected, the signature generates a Finding that contains:

**SigMetadata** (*object*)
: Essential metadata that provides context regarding the detected event's nature and potential threat level

**Event** (*object*)
: An exhaustive log of the triggering event, offering a detailed perspective of the issue

**Data** (*object*)
: Points out the specific path where the unexpected executable has been located, helping to pinpoint the source of the potential breach

## DEPENDENCIES

**Events Used:**

- magic_write: This event is activated when there's an attempt to introduce a new file or binary within the container's environment

## USE CASES

- **Container Security**: Monitor for unexpected executable drops in containerized environments that violate image immutability principles

- **Malware Detection**: Detect potential malware or backdoors being introduced into the system at runtime

- **Intrusion Detection**: Identify compromised containers where attackers are dropping additional tools or payloads

## RELATED EVENTS

- **magic_write**: File creation and modification events