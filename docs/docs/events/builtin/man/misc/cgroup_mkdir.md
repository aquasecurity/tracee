---
title: TRACEE-CGROUP-MKDIR
section: 1
header: Tracee Event Manual
---

## NAME

**cgroup_mkdir** - cgroup directory creation

## DESCRIPTION

Triggered when a new cgroup directory is created in the cgroup filesystem. This event tracks the creation of new cgroup directories, which often signals container initiation, process group creation, or resource management operations.

Since containers utilize control groups (cgroups) for resource management and isolation, monitoring cgroup directory creation provides valuable insights into container operations, resource allocations, and overall system container activity.

This event is useful for:

- **Container lifecycle monitoring**: Track container creation and resource allocation
- **Resource management**: Monitor cgroup-based resource control mechanisms
- **System activity analysis**: Understand process grouping and isolation patterns

## EVENT SETS

**none**

## DATA FIELDS

**cgroup_id** (*uint64*)
: The unique identifier for the cgroup

**cgroup_path** (*string*)
: The filesystem path to the cgroup directory

**hierarchy_id** (*uint32*)
: Identifier indicating the hierarchy level of the cgroup

## DEPENDENCIES

**Kernel Tracepoint:**

- cgroup_mkdir (raw tracepoint, required): Kernel tracepoint for cgroup directory creation

## USE CASES

- **Container monitoring**: Detect when new containers are created by tracking cgroup creation

- **Resource accounting**: Monitor cgroup creation for resource utilization tracking

- **Security monitoring**: Identify unexpected or malicious container creation activity

- **System administration**: Track container orchestration and resource management

- **Performance analysis**: Monitor container lifecycle and resource allocation patterns

## CGROUP HIERARCHY

Cgroups are organized in hierarchies:

- **v1 (legacy)**: Multiple hierarchies with different controllers
- **v2 (unified)**: Single unified hierarchy with all controllers
- **Hierarchy ID**: Identifies which cgroup hierarchy the directory belongs to

## CONTAINER RELATIONSHIP

Cgroup directory creation often correlates with:

- **Container creation**: New containers typically create new cgroup directories
- **Process isolation**: Applications using cgroups for resource control
- **Resource limits**: Setting up resource constraints and monitoring
- **Namespace isolation**: Combined with other isolation mechanisms

## PERFORMANCE CONSIDERATIONS

This event can be frequent in container-heavy environments. Consider filtering or adjusting monitoring scope based on:

- Specific cgroup paths of interest
- Container runtime patterns
- Resource management policies

## RELATED EVENTS

- **container_create**: High-level derived event for container creation
- **cgroup_rmdir**: Cgroup directory removal events
- **cgroup_attach_task**: Task attachment to cgroups
- **sched_process_fork**: Process creation that may trigger cgroup assignment