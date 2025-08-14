---
title: TRACEE-CONTAINER-CREATE
section: 1
header: Tracee Event Manual
---

## NAME

**container_create** - a new container is created

## DESCRIPTION

Triggered when a new container is created in the system. This derived event monitors container orchestration by tracking cgroup directory creation and examining metadata to identify new containers.

The event leverages the `cgroup_mkdir` event and examines metadata within `cgroupfs` subdirectories to determine if a new directory corresponds to a freshly instantiated container, gathering detailed information about the container including runtime, image details, and pod data.

This event is useful for:

- **Security monitoring**: Detecting unexpected or malicious container creation
- **Compliance audits**: Ensuring only approved container images are used
- **Performance monitoring**: Identifying resource-intensive containers

## EVENT SETS

**none**

## DATA FIELDS

**runtime** (*string*)
: The container runtime used (e.g., Docker, containerd)

**container_id** (*string*)
: The unique identifier for the container

**ctime** (*uint64*)
: Creation timestamp of the container

**container_image** (*string*)
: Image used to create the container

**container_image_digest** (*string*)
: Digest of the container image

**container_name** (*string*)
: Name of the container

**pod_name** (*string*)
: Name of the pod that this container belongs to (if applicable)

**pod_namespace** (*string*)
: Namespace of the pod

**pod_uid** (*string*)
: Unique identifier for the pod

**pod_sandbox** (*bool*)
: Indicates if the pod is acting as a sandbox

## DEPENDENCIES

**Source Events:**

- cgroup_mkdir (required): Primary event from which container_create is derived

**Derivation Logic:**

The event is derived from `cgroup_mkdir` by checking if the cgroup event belongs to a container root directory being created, then using the `cgroup_id` from the directory inode to retrieve container-specific information.

## USE CASES

- **Security monitoring**: Detect creation of unexpected or malicious containers

- **Compliance auditing**: Ensure only approved container images are used in production

- **Performance monitoring**: Identify newly created containers that may consume significant resources

- **Container lifecycle tracking**: Monitor container creation patterns and trends

## RELATED EVENTS

- **cgroup_mkdir**: Primary source event for container creation detection
- **container_remove**: Container deletion events
- **existing_container**: Events for already running containers