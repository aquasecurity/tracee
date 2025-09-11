---
title: TRACEE-REGISTER-CHRDEV
section: 1
header: Tracee Event Manual
---

## NAME

**register_chrdev** - character device registration monitoring

## DESCRIPTION

Triggered when a character device is registered with the kernel using the `__register_chrdev` function. This event captures the registration of character devices, which provide a stream-based interface for hardware devices, virtual devices, and other character-oriented device drivers.

Character device registration is performed by device drivers to make their functionality available to user space through device files in `/dev`, but can also be used by rootkits to establish communication channels or maintain persistence.

## EVENT SETS

**none**

## DATA FIELDS

**requested_major_number** (*uint32*)
: The major device number requested for the character device

**granted_major_number** (*uint32*)
: The major device number actually granted by the kernel

**char_device_name** (*string*)
: The name of the character device being registered

**char_device_fops** (*trace.Pointer*)
: The address of the file operations structure for the character device

## DEPENDENCIES

**Kernel Probe:**

- __register_chrdev (kprobe + kretprobe, required): Kernel character device registration function

## USE CASES

- **Device driver monitoring**: Track legitimate character device registration by drivers

- **Security monitoring**: Monitor character device registration for potential security threats

- **Rootkit detection**: Identify unauthorized character device registration that could indicate rootkit presence

- **System device tracking**: Track character device lifecycle and availability

- **Driver debugging**: Debug character device registration and driver initialization issues

## RELATED EVENTS

- **device_add**: General device addition events
- **do_init_module**: Kernel module loading that may register character devices
- **proc_create**: Procfs entry creation often associated with device drivers
- **Driver and module events**: Related kernel driver and module lifecycle monitoring
