
# Kernel Module Loading Detection

## Intro

The `KernelModuleLoading` signature is created to detect instances of kernel
module loading. Kernel modules are binaries designed to operate within the
kernel. By doing so, they run with elevated privileges and can directly interact
with the core of the operating system. As a result, malicious entities might aim
to load custom kernel modules, extending their capabilities and evading
detection by residing in the kernel, away from user space.

## Description

Loading kernel modules can be a legitimate activity, such as when administrators
aim to extend the kernel's capabilities. However, when unexpected, it can
signify a potentially harmful operation. The `KernelModuleLoading` signature is
designed to monitor for events that hint at kernel module loading and provide
alerts when detected.

## Purpose

The primary objective of the `KernelModuleLoading` signature is to ensure
real-time detection of kernel module loadings. This proactive detection is vital
in identifying potentially harmful modules before they execute their intended
functions, offering security personnel an opportunity to intervene.

## Metadata

- **ID**: TRC-1017
- **Version**: 1
- **Name**: Kernel module loading detected
- **EventName**: kernel_module_loading
- **Description**: Loading of a kernel module was detected. Kernel modules are meant for execution in the kernel environment. Adversaries might load such modules to enhance their functionalities and to elude detection by operating directly within the kernel, sidestepping user space.
- **Properties**:
  - **Severity**: 2 (Moderate threat level)
  - **Category**: persistence
  - **Technique**: Kernel Modules and Extensions
  - **Kubernetes_Technique**: N/A
  - **id**: attack-pattern--a1b52199-c8c5-438a-9ded-656f1d0888c6
  - **external_id**: T1547.006

## Findings

When a potential kernel module loading event is recognized, the signature
formulates a `Finding` data structure which encompasses:

- **SigMetadata**: Metadata detailing the perceived threat according to the specifications of the signature.
- **Event**: A thorough log of the particular event that caused the detection.
- **Data**: Currently labeled as `nil`, denoting there isn't any extra data backing the detection.

## Events Used

This signature predominantly observes the following events:

- `init_module`: Triggered during the initiation of a kernel module. When
detected, it suggests a module loading event.
- `security_kernel_read_file`: Engaged when there's a reading activity within
the kernel. This event is further inspected to check if the reading pertains to
"kernel-module" type, which would indicate module loading.
