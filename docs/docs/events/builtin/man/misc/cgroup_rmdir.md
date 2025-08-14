---
title: TRACEE-CGROUP-RMDIR
section: 1
header: Tracee Event Manual
---

## NAME

**cgroup_rmdir** - Event triggered when a cgroup directory is removed

## DESCRIPTION

The **cgroup_rmdir** event monitors the removal of directories within the cgroup filesystem. As containers are orchestrated and managed using control groups (cgroups), the removal of a directory often indicates the termination or scaling down of a container instance.

By monitoring these directory removal events, operators can capture crucial insights into container terminations, resource deallocations, and other significant container lifecycle events within the system.

This event is pivotal for administrators looking to scrutinize container lifecycle events and for understanding the orchestration dynamics in complex containerized environments.

## EVENT SETS

**none**

## DATA FIELDS

**cgroup_id** (*uint64*)
: The unique identifier associated with the cgroup being removed

**cgroup_path** (*string*)
: The file system path pointing to the cgroup directory that's being removed

**hierarchy_id** (*uint32*)
: Denotes the hierarchy level of the cgroup that's being removed

## DEPENDENCIES

**Kernel Tracepoint:**

- cgroup_rmdir (required): Kernel tracepoint for cgroup directory removal

## USE CASES

- **Container Termination Monitoring**: By tracing cgroup directory removals, the system can identify when containers are terminated, offering a perspective into system scaling dynamics and potential anomalies

- **Resource Cleanup**: Keeping track of the removal of cgroups helps in understanding resource deallocations and ensuring efficient resource usage across the infrastructure

## RELATED EVENTS

- **container_remove**: A derived event that focuses on providing detailed insights about the container corresponding to the removed cgroup directory