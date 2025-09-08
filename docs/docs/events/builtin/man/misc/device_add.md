---
title: TRACEE-DEVICE-ADD
section: 1
header: Tracee Event Manual
---

## NAME

**device_add** - device registration monitoring

## DESCRIPTION

Triggered when a new device is added to the kernel's device model using the `device_add` function. This event captures device registration operations performed by drivers when they register new hardware devices, virtual devices, or other device objects with the kernel.

Device registration is fundamental to the Linux device model and driver framework, but can also be used by rootkits or malicious drivers to register hidden devices or maintain persistence.

## EVENT SETS

**none**

## DATA FIELDS

**name** (*string*)
: The name of the device being added to the system

**parent_name** (*string*)
: The name of the parent device in the device hierarchy

## DEPENDENCIES

**Kernel Probe:**

- device_add (required): Kernel device addition function

## USE CASES

- **Hardware monitoring**: Track hardware device addition and driver registration

- **Driver security monitoring**: Monitor device registration for potential security threats

- **System device tracking**: Track device lifecycle and driver behavior

- **Rootkit detection**: Identify unauthorized device registration that could indicate rootkit presence

- **Device debugging**: Debug device registration and driver initialization issues

## RELATED EVENTS

- **register_chrdev**: Character device registration events
- **do_init_module**: Kernel module loading that may register devices
- **Driver events**: Related driver and hardware monitoring
- **Kernel module events**: Related kernel module and driver lifecycle monitoring
