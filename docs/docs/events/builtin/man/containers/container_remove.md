---
title: TRACEE-CONTAINER-REMOVE
section: 1
header: Tracee Event Manual
---

## NAME

**container_remove** - a container is terminated

## DESCRIPTION

Triggered when an existing container is terminated. This derived event monitors container lifecycle by tracking cgroup directory removal and examining metadata to identify container termination events.

The event leverages the `cgroup_rmdir` event and examines metadata within `cgroupfs` subdirectories to determine if a directory's removal correlates with a container's termination, capturing vital information about the terminated container.

This event is useful for:

- **Security monitoring**: Scrutinize container terminations for potential security breaches
- **Resource management**: Monitor container terminations to manage and reclaim system resources
- **System reliability**: Track container terminations to ensure stable operations

## EVENT SETS

**none**

## DATA FIELDS

**runtime** (*string*)
: The container runtime used (e.g., Docker, containerd)

**container_id** (*string*)
: The unique identifier of the terminated container

## DEPENDENCIES

**Source Events:**

- cgroup_rmdir (required): Primary event from which container_remove is derived

**Derivation Logic:**

The event is derived from `cgroup_rmdir` by assessing whether the cgroup event pertains to the root directory of a terminating container, then using the `cgroup_id` from the directory inode to gather container-specific information.

## USE CASES

- **Security monitoring**: Detect unexpected or unauthorized container terminations

- **Resource management**: Track container cleanup and resource reclamation

- **System reliability**: Monitor container lifecycle for operational stability

- **Compliance auditing**: Ensure proper container termination procedures

- **Incident response**: Investigate container termination patterns

## RELATED EVENTS

- **cgroup_rmdir**: Primary source event for container termination detection
- **container_create**: Container creation events
- **existing_container**: Events for already running containers