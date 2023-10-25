
# Detection of Dropped Executables

## Introduction

The `DroppedExecutable` signature is designed to identify instances where a new
executable file is introduced into the system during runtime. This type of
activity can often be a significant security concern, especially in
containerized environments where images are generally built with all necessary
binaries included. An unexpected or "dropped" binary can indicate an intrusion
or malicious activity within the container.

## Description

When running containers, a primary security principle is the immutability of
container images. This means that once a container image is built, it should
have all the binaries and libraries it needs to function. Any deviation from
this, such as dropping or introducing new executables during runtime, is often a
sign of malicious intent or an indication that the container's integrity has
been compromised.

The `DroppedExecutable` signature vigilantly monitors for such anomalies. If it
detects that a new executable has been introduced into the runtime environment,
it triggers an alert.

## Metadata

- **ID**: TRC-1022
- **Version**: 1
- **Name**: New executable dropped
- **EventName**: dropped_executable
- **Description**: Focuses on identifying instances where new executable files appear during the container's runtime. The presence of such unexpected binaries often suggests potential intrusions or that a threat actor has compromised the container.
- **Properties**:
  - **Severity**: 2 (Moderate)
  - **Category**: defense-evasion
  - **Technique**: Masquerading
  - **Kubernetes_Technique**: N/A
  - **id**: attack-pattern--42e8de7b-37b2-4258-905a-6897815e58e0
  - **external_id**: T1036

## Findings

Once an unexpected executable drop is detected, the signature generates a
`Finding` that contains:

- **SigMetadata**: Essential metadata that provides context regarding the detected event's nature and potential threat level.
- **Event**: An exhaustive log of the triggering event, offering a detailed perspective of the issue.
- **Data**: Points out the specific path where the unexpected executable has been located, helping to pinpoint the source of the potential breach.

## Events Used

Primarily, the signature watches for the event:

- `magic_write`: This event is activated when there's an attempt to introduce a
new file or binary within the container's environment. The signature then
inspects this event's data to deduce if the write operation involves a new
executable.
