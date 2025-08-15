---
title: TRACEE-SECURITY-TASK-SETRLIMIT
section: 1
header: Tracee Event Manual
---

## NAME

**security_task_setrlimit** - check permissions before setting task resource limits

## DESCRIPTION

This event is triggered by the Linux Security Module (LSM) hook when checking permissions before modifying a task's resource limits. Resource limits (rlimits) control the amount of system resources a process can use, such as CPU time, file size, or number of open files.

The event provides information about both the target process and the new limits being set, allowing monitoring of resource limit changes that could affect system stability or security. It occurs during the permission check phase, before the actual limit modification.

## EVENT SETS

**lsm**

## DATA FIELDS

**target_host_pid** (*uint32*)
: Process ID of the target task on the host

**resource** (*int32*)
: Resource type being limited (e.g., RLIMIT_CPU, RLIMIT_NOFILE)

**new_rlim_cur** (*uint64*)
: New soft limit value being set

**new_rlim_max** (*uint64*)
: New hard limit value being set

## DEPENDENCIES

- `security_task_setrlimit`: LSM hook for resource limit setting

## USE CASES

- **Resource control**: Monitor limit changes

- **Security monitoring**: Track privilege changes

- **System protection**: Prevent resource exhaustion

- **Compliance**: Verify resource constraints

## RESOURCE TYPES

Common resource limits:

- **RLIMIT_CPU**: CPU time limit
- **RLIMIT_FSIZE**: Maximum file size
- **RLIMIT_DATA**: Data segment size
- **RLIMIT_STACK**: Stack size limit
- **RLIMIT_CORE**: Core file size
- **RLIMIT_RSS**: Resident set size
- **RLIMIT_NPROC**: Number of processes
- **RLIMIT_NOFILE**: Open file descriptors
- **RLIMIT_MEMLOCK**: Locked memory
- **RLIMIT_AS**: Address space limit

## LIMIT TYPES

Understanding limit values:

- **Soft limit (rlim_cur)**:
  - Current enforcement level
  - Can be changed by process
  - Must be ≤ hard limit
  - Generates signal when exceeded

- **Hard limit (rlim_max)**:
  - Maximum allowed value
  - Requires privileges to increase
  - Cannot be exceeded by soft limit
  - Absolute resource boundary

## SECURITY IMPLICATIONS

Important security aspects:

- **Resource exhaustion**: Prevent DoS
- **Process constraints**: Control behavior
- **System stability**: Protect resources
- **Privilege escalation**: Limit scope
- **Container isolation**: Resource boundaries

## RELATED EVENTS

- **setrlimit**: System call for setting limits
- **prlimit64**: Process resource limits
- **security_bprm_check**: Binary execution checks
- **security_task_kill**: Process signal checks
