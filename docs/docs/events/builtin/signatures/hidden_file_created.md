
# Hidden Executable File Creation Detection

## Intro

The `HiddenFileCreated` signature targets the identification of furtive attempts
to create hidden executable files, specifically ELF (Executable and Linkable
Format) files, in the system. By convention, in Unix-like systems, any file or
directory that starts with a dot (.) is hidden from standard directory listings.

## Description

Hidden files and directories are commonly used in Linux and Unix systems to
store configuration files and user preferences. However, malicious actors can
exploit this convention to hide their activities, files, and tools from standard
monitoring and listing tools. The creation of a hidden ELF file, in particular,
can suggest that an attacker or malicious software is attempting to operate
undetected on the system.

The `HiddenFileCreated` signature closely watches for these furtive actions by
scanning the file paths for the presence of the "hidden" pattern, i.e., starting
with a "/.". Combined with checking the magic bytes of files to determine if
they are ELF format, this signature provides a robust method to detect hidden
executable file creation.

## Purpose

This signature's principal objective is to detect and flag the concealed
creation of ELF files. Monitoring such actions is crucial since, while there can
be legitimate reasons to have hidden executables, the unauthorized or unexpected
creation of such files can be an early indication of malicious activities.

## Metadata

- **ID**: TRC-1015
- **Version**: 1
- **Name**: Hidden executable creation detected
- **EventName**: hidden_file_created
- **Description**: The signature identifies the creation of hidden executable ELF files in the system. While there can be genuine reasons for having hidden executables, the unauthorized or unforeseen creation of such files can be indicative of malicious intent.
- **Properties**:
  - **Severity**: 2 (Moderate threat level)
  - **Category**: defense-evasion
  - **Technique**: Hidden Files and Directories
  - **Kubernetes_Technique**: N/A
  - **id**: attack-pattern--ec8fc7e2-b356-455c-8db5-2e37be158e7d
  - **external_id**: T1564.001

## Findings

When an anomaly is detected, the signature returns a `Finding` data structure,
which comprises:

- **SigMetadata**: Metadata that provides detailed information about the detected threat, based on the signature's definitions.
- **Event**: An exhaustive description of the particular event that invoked the signature's alert mechanism.
- **Data**: Currently initialized to `nil`, indicating that no additional data is associated with the alert.

## Events Used

The primary event that powers this signature's functionality is:

- `magic_write`: Triggered when specific byte sequences, or "magic bytes," are
written to a file. The signature checks the bytes to see if they correspond to
an ELF file and examines the file path to determine if the ELF file is hidden.
