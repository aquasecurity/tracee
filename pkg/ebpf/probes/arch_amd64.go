//go:build amd64
// +build amd64

package probes

const SyscallPrefix = "__x64_sys_"
const SyscallPrefixCompat = "__ia32_sys_"
const SyscallPrefixCompat2 = "__ia32_compat_sys_"
