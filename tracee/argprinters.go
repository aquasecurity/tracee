package tracee

import (
	"strconv"
	"strings"
)

// PrintMknodMode prints the `mode` bitmask argument of the `mknod` syscall
// http://man7.org/linux/man-pages/man7/inode.7.html
func PrintMknodMode(mode uint32) string {
	var f []string

	// File Type
	switch {
	case mode&0140000 == 0140000:
		f = append(f, "S_IFSOCK")
	case mode&0120000 == 0120000:
		f = append(f, "S_IFLNK")
	case mode&0100000 == 0100000:
		f = append(f, "S_IFREG")
	case mode&060000 == 060000:
		f = append(f, "S_IFBLK")
	case mode&040000 == 040000:
		f = append(f, "S_IFDIR")
	case mode&020000 == 020000:
		f = append(f, "S_IFCHR")
	case mode&010000 == 010000:
		f = append(f, "S_IFIFO")
	default:
		f = append(f, "invalid file type")
	}

	// File Mode
	// Owner
	if mode&00700 == 00700 {
		f = append(f, "S_IRWXU")
	} else {
		if mode&00400 == 00400 {
			f = append(f, "S_IRUSR")
		}
		if mode&00200 == 00200 {
			f = append(f, "S_IWUSR")
		}
		if mode&00100 == 00100 {
			f = append(f, "S_IXUSR")
		}
	}
	// Group
	if mode&00070 == 00070 {
		f = append(f, "S_IRWXG")
	} else {
		if mode&00040 == 00040 {
			f = append(f, "S_IRGRP")
		}
		if mode&00020 == 00020 {
			f = append(f, "S_IWGRP")
		}
		if mode&00010 == 00010 {
			f = append(f, "S_IXGRP")
		}
	}
	// Others
	if mode&00007 == 00007 {
		f = append(f, "S_IRWXO")
	} else {
		if mode&00004 == 00004 {
			f = append(f, "S_IROTH")
		}
		if mode&00002 == 00002 {
			f = append(f, "S_IWOTH")
		}
		if mode&00001 == 00001 {
			f = append(f, "S_IXOTH")
		}
	}

	return strings.Join(f, "|")
}

// PrintMmapProt prints the `prot` bitmask argument of the `mmap` syscall
// http://man7.org/linux/man-pages/man2/mmap.2.html
// https://elixir.bootlin.com/linux/v5.5.3/source/include/uapi/asm-generic/mman-common.h#L10
func PrintMmapProt(prot uint32) string {
	var f []string
	if prot == 0x0 {
		f = append(f, "PROT_NONE")
	} else {
		if prot&0x01 == 0x01 {
			f = append(f, "PROT_READ")
		}
		if prot&0x02 == 0x02 {
			f = append(f, "PROT_WRITE")
		}
		if prot&0x04 == 0x04 {
			f = append(f, "PROT_EXEC")
		}
	}
	return strings.Join(f, "|")
}

// PrintOpenFlags prints the `flags` bitmask argument of the `open` syscall
// http://man7.org/linux/man-pages/man2/open.2.html
// https://elixir.bootlin.com/linux/v5.5.3/source/include/uapi/asm-generic/fcntl.h
func PrintOpenFlags(flags uint32) string {
	var f []string

	//access mode
	switch {
	case flags&00 == 00:
		f = append(f, "O_RDONLY")
	case flags&01 == 01:
		f = append(f, "O_WRONLY")
	case flags&04 == 0x02:
		f = append(f, "O_RDWR")
	}

	// file creation and status flags
	if flags&0100 == 0100 {
		f = append(f, "O_CREAT")
	}
	if flags&0200 == 0200 {
		f = append(f, "O_EXCL")
	}
	if flags&0400 == 0400 {
		f = append(f, "O_NOCTTY")
	}
	if flags&01000 == 01000 {
		f = append(f, "O_TRUNC")
	}
	if flags&02000 == 02000 {
		f = append(f, "O_APPEND")
	}
	if flags&04000 == 04000 {
		f = append(f, "O_NONBLOCK")
	}
	if flags&04010000 == 04010000 {
		f = append(f, "O_SYNC")
	}
	if flags&020000 == 020000 {
		f = append(f, "O_ASYNC")
	}
	if flags&0100000 == 0100000 {
		f = append(f, "O_LARGEFILE")
	}
	if flags&0200000 == 0200000 {
		f = append(f, "O_DIRECTORY")
	}
	if flags&0400000 == 0400000 {
		f = append(f, "O_NOFOLLOW")
	}
	if flags&02000000 == 02000000 {
		f = append(f, "O_CLOEXEC")
	}
	if flags&040000 == 040000 {
		f = append(f, "O_DIRECT")
	}
	if flags&01000000 == 01000000 {
		f = append(f, "O_NOATIME")
	}
	if flags&010000000 == 010000000 {
		f = append(f, "O_PATH")
	}
	if flags&020000000 == 020000000 {
		f = append(f, "O_TMPFILE")
	}

	return strings.Join(f, "|")
}

// http://man7.org/linux/man-pages/man2/access.2.html
// https://pubs.opengroup.org/onlinepubs/9699919799/basedefs/unistd.h.html#tag_13_77_03_04
func PrintAccessMode(mode uint32) string {
	var f []string
	if mode == 0x0 {
		f = append(f, "F_OK")
	} else {
		if mode&0x01 == 0x01 {
			f = append(f, "X_OK")
		}
		if mode&0x02 == 0x02 {
			f = append(f, "W_OK")
		}
		if mode&0x04 == 0x04 {
			f = append(f, "R_OK")
		}
	}
	return strings.Join(f, "|")
}

// PrintExecFlags prints the `flags` bitmask argument of the `execve` syscall
// http://man7.org/linux/man-pages/man2/axecveat.2.html
// https://elixir.bootlin.com/linux/latest/source/include/uapi/linux/fcntl.h#L94
func PrintExecFlags(flags uint32) string {
	var f []string
	if flags&0x100 == 0x100 {
		f = append(f, "AT_EMPTY_PATH")
	}
	if flags&0x1000 == 0x1000 {
		f = append(f, "AT_SYMLINK_NOFOLLOW")
	}
	return strings.Join(f, "|")
}

// PrintSocketType prints the `type` bitmask argument of the `socket` syscall
// http://man7.org/linux/man-pages/man2/socket.2.html
func PrintSocketType(st uint32) string {
	var socketTypes = []string{
		"SOCK_STREAM",
		"SOCK_DGRAM",
		"SOCK_RAW",
		"SOCK_RDM",
		"SOCK_SEQPACKET",
		"SOCK_DCCP",
		"SOCK_PACKET",
	}
	var f []string
	if int(st) < len(socketTypes) {
		f = append(f, socketTypes[st])
	} else {
		f = append(f, strconv.Itoa(int(st)))
	}
	if st&000004000 == 000004000 {
		f = append(f, "SOCK_NONBLOCK")
	}
	if st&002000000 == 002000000 {
		f = append(f, "SOCK_CLOEXEC")
	}
	return strings.Join(f, "|")
}

// PrintSocketDomain prints the `domain` bitmask argument of the `socket` syscall
// http://man7.org/linux/man-pages/man2/socket.2.html
func PrintSocketDomain(sd uint32) string {
	var socketDomains = []string{
		"AF_UNSPEC",
		"AF_UNIX",
		"AF_INET",
		"AF_AX25",
		"AF_IPX",
		"AF_APPLETALK",
		"AF_NETROM",
		"AF_BRIDGE",
		"AF_ATMPVC",
		"AF_X25",
		"AF_INET6",
		"AF_ROSE",
		"AF_DECnet",
		"AF_NETBEUI",
		"AF_SECURITY",
		"AF_KEY",
		"AF_NETLINK",
		"AF_PACKET",
		"AF_ASH",
		"AF_ECONET",
		"AF_ATMSVC",
		"AF_RDS",
		"AF_SNA",
		"AF_IRDA",
		"AF_PPPOX",
		"AF_WANPIPE",
		"AF_LLC",
		"AF_IB",
		"AF_MPLS",
		"AF_CAN",
		"AF_TIPC",
		"AF_BLUETOOTH",
		"AF_IUCV",
		"AF_RXRPC",
		"AF_ISDN",
		"AF_PHONET",
		"AF_IEEE802154",
		"AF_CAIF",
		"AF_ALG",
		"AF_NFC",
		"AF_VSOCK",
		"AF_KCM",
		"AF_QIPCRTR",
		"AF_SMC",
		"AF_XDP",
	}
	var res string
	if int(sd) < len(socketDomains) {
		res = socketDomains[sd]
	} else {
		res = strconv.Itoa(int(sd))
	}
	return res
}

// PrintCapability prints the `capability` bitmask argument of the `cap_capable` function
// include/uapi/linux/capability.h
func PrintCapability(cap int32) string {
	var capabilities = []string{
		"CAP_CHOWN",
		"CAP_DAC_OVERRIDE",
		"CAP_DAC_READ_SEARCH",
		"CAP_FOWNER",
		"CAP_FSETID",
		"CAP_KILL",
		"CAP_SETGID",
		"CAP_SETUID",
		"CAP_SETPCAP",
		"CAP_LINUX_IMMUTABLE",
		"CAP_NET_BIND_SERVICE",
		"CAP_NET_BROADCAST",
		"CAP_NET_ADMIN",
		"CAP_NET_RAW",
		"CAP_IPC_LOCK",
		"CAP_IPC_OWNER",
		"CAP_SYS_MODULE",
		"CAP_SYS_RAWIO",
		"CAP_SYS_CHROOT",
		"CAP_SYS_PTRACE",
		"CAP_SYS_PACCT",
		"CAP_SYS_ADMIN",
		"CAP_SYS_BOOT",
		"CAP_SYS_NICE",
		"CAP_SYS_RESOURCE",
		"CAP_SYS_TIME",
		"CAP_SYS_TTY_CONFIG",
		"CAP_MKNOD",
		"CAP_LEASE",
		"CAP_AUDIT_WRITE",
		"CAP_AUDIT_CONTROL",
		"CAP_SETFCAP",
		"CAP_MAC_OVERRIDE",
		"CAP_MAC_ADMIN",
		"CAP_SYSLOG",
		"CAP_WAKE_ALARM",
		"CAP_BLOCK_SUSPEND",
		"CAP_AUDIT_READ",
	}
	var res string
	if int(cap) < len(capabilities) {
		res = capabilities[cap]
	} else {
		res = strconv.Itoa(int(cap))
	}
	return res
}
