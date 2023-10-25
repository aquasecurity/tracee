
# Default dynamic loader modification detection

## Intro

The `DefaultLoaderModification` signature detects unauthorized or unexpected
changes to the default dynamic loader on a Linux system.

Dynamic loaders play a crucial role in the execution of applications by loading
necessary shared libraries before the main program runs. Unauthorized
modifications to this component could allow an attacker to manipulate the
behavior of almost every application on the system.

## Description

Dynamic loaders, which are located in directories like `/lib` and `/usr/lib`,
are responsible for loading shared libraries for dynamically linked
applications. By manipulating the dynamic loader, an attacker could control or
alter the way an application behaves, making it a potent attack vector.

Such modifications could be used to achieve persistence, bypass security
controls, or intercept sensitive information. Recognizing changes to these
loaders is, therefore, of paramount importance to maintain system integrity.

## Purpose

This signature focuses on identifying unauthorized modifications to the default
dynamic loader. Monitoring such changes helps in the early detection of
potential system compromises or attempts by adversaries to inject malicious code
into application execution contexts.

## Metadata

- **ID**: TRC-1012
- **Version**: 1
- **Name**: Default dynamic loader modification detected
- **EventName**: default_loader_mod
- **Description**: Monitors for modifications to the default dynamic loader, which is essential for the execution of dynamically linked applications. Any unexpected changes could signify an attacker's attempt to control or manipulate application behavior, bypass security mechanisms, or achieve persistence on the system.
- **Properties**:
  - **Severity**: 3
  - **Category**: defense-evasion
  - **Technique**: Hijack Execution Flow
  - **Kubernetes_Technique**: N/A
  - **id**: attack-pattern--aedfca76-3b30-4866-b2aa-0f1d7fd1e4b6
  - **external_id**: T1574

## Findings

When a potential modification to the default dynamic loader is identified, a
`Finding` is generated, which contains detailed information about the event and
associated threat metadata.

## Events Used

The signature is mainly interested in two events:

- `security_file_open`: This event is triggered when a file is opened. This
signature particularly focuses on instances where the file is opened with write
permissions.

- `security_inode_rename`: This event indicates the renaming of a file or
directory, which could be an indicator of an attacker trying to replace the
original loader with a malicious one.

If the path associated with these events matches the pattern of a default dynamic loader, an alert is raised.
