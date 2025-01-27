#ifndef __VMLINUX_MISSING_H__
#define __VMLINUX_MISSING_H__

// NOTE: vmlinux.h contains kernel BTF types but not macros (put it here)

#include <vmlinux.h>

#define ULLONG_MAX (~0ULL)

#define inet_daddr     sk.__sk_common.skc_daddr
#define inet_rcv_saddr sk.__sk_common.skc_rcv_saddr
#define inet_dport     sk.__sk_common.skc_dport
#define inet_num       sk.__sk_common.skc_num

#define sk_node             __sk_common.skc_node
#define sk_nulls_node       __sk_common.skc_nulls_node
#define sk_refcnt           __sk_common.skc_refcnt
#define sk_tx_queue_mapping __sk_common.skc_tx_queue_mapping

#define sk_dontcopy_begin __sk_common.skc_dontcopy_begin
#define sk_dontcopy_end   __sk_common.skc_dontcopy_end
#define sk_hash           __sk_common.skc_hash
#define sk_portpair       __sk_common.skc_portpair
#define sk_num            __sk_common.skc_num
#define sk_dport          __sk_common.skc_dport
#define sk_addrpair       __sk_common.skc_addrpair
#define sk_daddr          __sk_common.skc_daddr
#define sk_rcv_saddr      __sk_common.skc_rcv_saddr
#define sk_family         __sk_common.skc_family
#define sk_state          __sk_common.skc_state
#define sk_reuse          __sk_common.skc_reuse
#define sk_reuseport      __sk_common.skc_reuseport
#define sk_ipv6only       __sk_common.skc_ipv6only
#define sk_net_refcnt     __sk_common.skc_net_refcnt
#define sk_bound_dev_if   __sk_common.skc_bound_dev_if
#define sk_bind_node      __sk_common.skc_bind_node
#define sk_prot           __sk_common.skc_prot
#define sk_net            __sk_common.skc_net
#define sk_v6_daddr       __sk_common.skc_v6_daddr
#define sk_v6_rcv_saddr   __sk_common.skc_v6_rcv_saddr
#define sk_cookie         __sk_common.skc_cookie
#define sk_incoming_cpu   __sk_common.skc_incoming_cpu
#define sk_flags          __sk_common.skc_flags
#define sk_rxhash         __sk_common.skc_rxhash

#define ICMP_ECHO     8
#define ICMP_EXT_ECHO 42

#define ICMPV6_ECHO_REQUEST 128

#define PF_SIGNALED 0x00000400 /* Killed by a signal */
#define PF_KTHREAD  0x00200000 /* I am a kernel thread */

#define TASK_COMM_LEN 16

#define PROC_SUPER_MAGIC 0x9fa0

// include/uapi/linux/const.h
#define __AC(X, Y) (X##Y)
#define _AC(X, Y)  __AC(X, Y)
#define _UL(x)     (_AC(x, UL))

// ioctl
#define _IOC_NRBITS   8
#define _IOC_TYPEBITS 8

#ifndef _IOC_SIZEBITS
    #define _IOC_SIZEBITS 14
#endif

#define _IOC_NRSHIFT   0
#define _IOC_TYPESHIFT (_IOC_NRSHIFT + _IOC_NRBITS)
#define _IOC_SIZESHIFT (_IOC_TYPESHIFT + _IOC_TYPEBITS)
#define _IOC_DIRSHIFT  (_IOC_SIZESHIFT + _IOC_SIZEBITS)

#ifndef _IOC_WRITE
    #define _IOC_WRITE 1U
#endif

#define _IOC(dir, type, nr, size)                                                                  \
    (((dir) << _IOC_DIRSHIFT) | ((type) << _IOC_TYPESHIFT) | ((nr) << _IOC_NRSHIFT) |              \
     ((size) << _IOC_SIZESHIFT))

#define _IOC_TYPECHECK(t)      (sizeof(t))
#define _IOW(type, nr, size)   _IOC(_IOC_WRITE, (type), (nr), (_IOC_TYPECHECK(size)))
#define PERF_EVENT_IOC_SET_BPF _IOW('$', 8, __u32)

enum perf_type_id
{
    PERF_TYPE_HARDWARE = 0,
    PERF_TYPE_SOFTWARE = 1,
    PERF_TYPE_TRACEPOINT = 2,
    PERF_TYPE_HW_CACHE = 3,
    PERF_TYPE_RAW = 4,
    PERF_TYPE_BREAKPOINT = 5,

    PERF_TYPE_MAX, /* non-ABI */
};

/*=============================== ARCH SPECIFIC ===========================*/
#if defined(__TARGET_ARCH_x86)

    #define TS_COMPAT 0x0002 /* 32bit syscall active (64BIT)*/

    // arch/x86/include/asm/page_64_types.h
    #define KASAN_STACK_ORDER                                                                      \
        0 /* We implicitly assume here that KASAN (memory debugger) is disabled */
    #define THREAD_SIZE_ORDER (2 + KASAN_STACK_ORDER)
    #define THREAD_SIZE       (PAGE_SIZE << THREAD_SIZE_ORDER)

    #define PAGE_SHIFT 12
    #define PAGE_SIZE  (_AC(1, UL) << PAGE_SHIFT)
    #define PAGE_MASK  (~(PAGE_SIZE - 1))

    #define TOP_OF_KERNEL_STACK_PADDING 0

#elif defined(__TARGET_ARCH_arm64)

    // extern bool CONFIG_ARM64_PAGE_SHIFT __kconfig;
    //  arch/arm64/include/asm/page-def.h
    //#define PAGE_SHIFT        CONFIG_ARM64_PAGE_SHIFT
    //  as a temporary workaround for failing builds, use the default value of PAGE_SHIFT
    #define PAGE_SHIFT       12
    #define PAGE_SIZE        (_AC(1, UL) << PAGE_SHIFT)

    // arch/arm64/include/asm/thread_info.h
    #define _TIF_32BIT       (1 << 22)

    // arch/arm64/include/asm/memory.h
    //#define MIN_THREAD_SHIFT	(14 + KASAN_THREAD_SHIFT)
    #define MIN_THREAD_SHIFT 14 // default value if KASAN is disabled (which it should be usually)

    // this can also be PAGE_SHIFT if (MIN_THREAD_SHIFT < PAGE_SHIFT) however here 14 > 12
    // so we choose MIN_THREAD_SHIFT
    #define THREAD_SHIFT     MIN_THREAD_SHIFT
    #define THREAD_SIZE      (_UL(1) << THREAD_SHIFT)

#endif

/*=============================== ARCH SPECIFIC ===========================*/

#define VM_NONE   0x00000000
#define VM_READ   0x00000001
#define VM_WRITE  0x00000002
#define VM_EXEC   0x00000004
#define VM_SHARED 0x00000008

#define TC_ACT_UNSPEC     (-1)
#define TC_ACT_OK         0
#define TC_ACT_RECLASSIFY 1
#define TC_ACT_SHOT       2
#define TC_ACT_PIPE       3
#define TC_ACT_STOLEN     4
#define TC_ACT_QUEUED     5
#define TC_ACT_REPEAT     6
#define TC_ACT_REDIRECT   7

#define ETH_P_IP   0x0800
#define ETH_P_IPV6 0x86DD

#define s6_addr   in6_u.u6_addr8
#define s6_addr16 in6_u.u6_addr16
#define s6_addr32 in6_u.u6_addr32

#define __user

#define S_IFMT   00170000
#define S_IFSOCK 0140000
#define S_IFLNK  0120000
#define S_IFREG  0100000
#define S_IFBLK  0060000
#define S_IFDIR  0040000
#define S_IFCHR  0020000
#define S_IFIFO  0010000
#define S_ISUID  0004000
#define S_ISGID  0002000
#define S_ISVTX  0001000

#define CAP_OPT_NONE    0x0
#define CAP_OPT_NOAUDIT 0b10
#define CAP_OPT_INSETID 0b100

static inline bool ipv6_addr_any(const struct in6_addr *a)
{
    return (a->in6_u.u6_addr32[0] | a->in6_u.u6_addr32[1] | a->in6_u.u6_addr32[2] |
            a->in6_u.u6_addr32[3]) == 0;
}

static inline struct inet_sock *inet_sk(const struct sock *sk)
{
    return (struct inet_sock *) sk;
}

#define PIPE_BUF_FLAG_CAN_MERGE 0x10 /* can merge buffers */

#define __get_node_addr(array, node_type, index)                                                   \
    ((node_type *) ((void *) array + (index * bpf_core_type_size(node_type))))
#define get_node_addr(array, index) __get_node_addr(array, typeof(*array), index)

// NOTE: new network code

// Protocol families
#define PF_UNSPEC    0
#define PF_LOCAL     1
#define PF_UNIX      PF_LOCAL
#define PF_FILE      PF_LOCAL
#define PF_INET      2
#define PF_BRIDGE    7
#define PF_INET6     10
#define PF_KEY       15
#define PF_NETLINK   16
#define PF_ROUTE     PF_NETLINK
#define PF_PACKET    17
#define PF_IB        27
#define PF_MPLS      28
#define PF_BLUETOOTH 31
#define PF_VSOCK     40
#define PF_XDP       44

/* Address families.  */
#define AF_UNSPEC    PF_UNSPEC
#define AF_LOCAL     PF_LOCAL
#define AF_UNIX      PF_UNIX
#define AF_FILE      PF_FILE
#define AF_INET      PF_INET
#define AF_INET6     PF_INET6
#define AF_KEY       PF_KEY
#define AF_NETLINK   PF_NETLINK
#define AF_ROUTE     PF_ROUTE
#define AF_PACKET    PF_PACKET
#define AF_IB        PF_IB
#define AF_MPLS      PF_MPLS
#define AF_BLUETOOTH PF_BLUETOOTH
#define AF_VSOCK     PF_VSOCK
#define AF_XDP       PF_XDP

#ifndef IPPROTO_IPIP
    #define IPPROTO_IPIP 4
#endif

#ifndef IPPROTO_DCCP
    #define IPPROTO_DCCP 33
#endif

#ifndef IPPROTO_IPV6
    #define IPPROTO_IPV6 41
#endif

#ifndef IPPROTO_ICMPV6
    #define IPPROTO_ICMPV6 58
#endif

#ifndef IPPROTO_SCTP
    #define IPPROTO_SCTP 132
#endif

#ifndef IPPROTO_UDPLITE
    #define IPPROTO_UDPLITE 136
#endif

#define IPPROTO_HOPOPTS  0   // IPv6 hop-by-hop options
#define IPPROTO_ROUTING  43  // IPv6 routing header
#define IPPROTO_FRAGMENT 44  // IPv6 fragmentation header
#define IPPROTO_ICMPV6   58  // ICMPv6
#define IPPROTO_NONE     59  // IPv6 no next header
#define IPPROTO_DSTOPTS  60  // IPv6 destination options
#define IPPROTO_MH       135 // IPv6 mobility header

#endif
