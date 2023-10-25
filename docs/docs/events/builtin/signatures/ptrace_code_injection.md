
# Ptrace Code Injection Detection

## Intro

The `PtraceCodeInjection` signature is tailored to identify attempts at code
injection through the use of the `ptrace` system call. The signature
specifically looks for the `PTRACE_POKETEXT` and `PTRACE_POKEDATA` requests,
commonly used for altering the target process's memory. Code injection is a
sophisticated attack vector, allowing attackers to run arbitrary code within the
context of another process.

## Description

Code injection is a pervasive technique used by adversaries to execute malicious
payloads within other processes, evading detection and leveraging the
permissions of the injected process. This can enable them to operate stealthily,
as the malicious operations appear to be coming from a legitimate process.

The `ptrace` system call, especially with the `PTRACE_POKETEXT` and
`PTRACE_POKEDATA` requests, can be exploited for such purposes. By monitoring
these specific requests, this signature can detect attempts to write to another
process's memory, signaling potential code injection attempts.

## Purpose

The primary objective of the `PtraceCodeInjection` signature is to detect and
raise alerts regarding potential code injection attempts using `ptrace`. Such
detection is vital because, if successful, the attacker can assume the identity
of another process, potentially gaining elevated privileges and evading
detection mechanisms.

## Metadata

- **ID**: TRC-103
- **Version**: 1
- **Name**: Code injection detected using ptrace
- **EventName**: ptrace_code_injection
- **Description**: The signature is specifically crafted to detect potential code injection attempts into another process using the `ptrace` system call. Code injection is a method used by adversaries to execute malicious code within the confines of another process, effectively evading detection and leveraging the permissions of the injected process.
- **Properties**:
  - **Severity**: 3 (Moderate to high threat level)
  - **Category**: defense-evasion
  - **Technique**: Ptrace System Calls
  - **Kubernetes_Technique**: N/A
  - **id**: attack-pattern--ea016b56-ae0e-47fe-967a-cc0ad51af67f
  - **external_id**: T1055.008

## Findings

Upon detecting a potential code injection attempt, the signature returns a
`Finding` data structure, which entails:

- **SigMetadata**: Metadata detailing the threat according to the signature's specifications.
- **Event**: Provides an in-depth account of the specific event that triggered the signature's detection mechanism.
- **Data**: Currently set to `nil`, indicating no additional data accompanies this structure.

## Events Used

The detection capabilities of this signature rely primarily on the following event:

- `ptrace`: Triggered when the `ptrace` system call is utilized. The signature
meticulously evaluates the request type to determine if there's an invocation of
either `PTRACE_POKETEXT` or `PTRACE_POKEDATA`, indicating a potential code
injection attempt.
