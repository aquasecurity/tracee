# About Kernel symbols

As explained in the [prerequisites](../install/prerequisites.md) doc, Tracee 
needs the kernel symbol table for some operations.

A Linux kernel might lack the `/proc/kallsyms` file due to:

**Kernel Configuration**: If compiled without `CONFIG_KALLSYMS`, the kernel
won't have this file. This option enables the kernel symbol table, used mainly
for debugging.

**Security Protocols**: Some systems might hide kernel symbols to prevent
potential exploits. The `/proc/kallsyms` file could appear incomplete or even
empty to non-root users. The `CONFIG_KALLSYMS_ALL` option ensures all symbols
are visible.

The Linux kernel also offers a setting, `/proc/sys/kernel/kptr_restrict`, to
control kernel symbol visibility:

- **0**: No restrictions.
- **1**: Hide from non-privileged users.
- **2**: Hide from all users.
