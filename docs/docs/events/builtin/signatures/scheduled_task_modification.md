
# Scheduled tasks modification detected

## Intro

The `ScheduledTaskModification` signature aims to identify when scheduled tasks
or their configurations have been tampered with. Scheduled tasks are a common
mechanism used on Linux-based systems to execute commands or scripts at
predefined times or after specific intervals. However, adversaries might
manipulate these tasks for malicious purposes, such as maintaining persistence
after a reboot.

## Description

This signature focuses on the various aspects of task scheduling, specifically
revolving around the `crontab` and its associated files and directories.

Monitoring alterations to these files and directories is critical because
changes could be indicative of unauthorized activities. The signature also
identifies when certain commands related to scheduling are executed, ensuring a
broader coverage against potential threats.

## Purpose

This signature primarily aims to safeguard systems against unauthorized or
malicious modifications to scheduled tasks. By detecting such changes, it alerts
administrators or security systems, helping prevent potential breaches or
maintaining a persistent presence by adversaries.

## Metadata

- **ID**: TRC-1027
- **Version**: 1
- **Name**: Scheduled tasks modification detected
- **EventName**: scheduled_task_mod
- **Description**: Monitors for changes to task scheduling configurations or the execution of scheduling-related commands. Detecting such modifications is crucial because adversaries can use these tasks for persistence mechanisms.
- **Properties**:
  - **Severity**: 2
  - **Category**: persistence
  - **Technique**: Cron
  - **Kubernetes_Technique**: N/A
  - **id**: attack-pattern--2acf44aa-542f-4366-b4eb-55ef5747759c
  - **external_id**: T1053.003

## Findings

Upon detecting any of the predefined suspicious actions, the signature triggers a `Finding` structure, signaling potential threats. The findings don't contain specific data fields related to the event, except for the event's metadata.

## Events Used

This signature primarily listens to three event types:

1. `security_file_open` - Checks if a scheduling-related file was opened, specifically with write permissions.
2. `security_inode_rename` - Monitors if any of the scheduling-related files or directories got renamed.
3. `sched_process_exec` - Listens for the execution of specific commands related to task scheduling.

By monitoring these events, the signature offers a comprehensive safeguard
against the unauthorized alteration of scheduled tasks.
