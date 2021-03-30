/*
 * The purpose of this file is to define macros
 * that tracee.bpf.c relies on which are defined
 * in linux kernel headers but not in vmlinux.h 
 * 
 * vmlinux.h is generated from BTF information
 * in vmlinux but this does not include macros.
 * 
 */ 

#ifndef __TRACEE_MISSING_MACROS_H__
#define __TRACEE_MISSING_MACROS_H__

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

#define TS_COMPAT 0x0002    /* 32bit syscall active (64BIT)*/

#define TASK_COMM_LEN 16

#define THREAD_SIZE_ORDER 1

#define THREAD_SIZE (2*PAGE_SIZE)

#define PAGE_SHIFT 12
#define PAGE_SIZE  (_AC(1,UL) << PAGE_SHIFT)
#define PAGE_MASK  (~(PAGE_SIZE-1))

#define _AC(X,Y)    X

#ifdef CONFIG_X86_32
# ifdef CONFIG_VM86
#  define TOP_OF_KERNEL_STACK_PADDING 16
# else
#  define TOP_OF_KERNEL_STACK_PADDING 8
# endif
#else
# define TOP_OF_KERNEL_STACK_PADDING 0
#endif

/* Supported address families. */
#define AF_UNSPEC      0
#define AF_UNIX        1          /* Unix domain sockets */
#define AF_LOCAL       1          /* POSIX name for AF_UNIX */
#define AF_INET        2          /* Internet IP Protocol */
#define AF_AX25        3          /* Amateur Radio AX.25 */
#define AF_IPX         4          /* Novell IPX */
#define AF_APPLETALK   5          /* AppleTalk DDP */
#define AF_NETROM      6          /* Amateur Radio NET/ROM */
#define AF_BRIDGE      7          /* Multiprotocol bridge */
#define AF_ATMPVC      8          /* ATM PVCs */
#define AF_X25         9          /* Reserved for X.25 project */
#define AF_INET6       10         /* IP version 6 */
#define AF_ROSE        11         /* Amateur Radio X.25 PLP */
#define AF_DECnet      12         /* Reserved for DECnet project */
#define AF_NETBEUI     13         /* Reserved for 802.2LLC project */
#define AF_SECURITY    14         /* Security callback pseudo AF */
#define AF_KEY         15         /* PF_KEY key management API */
#define AF_NETLINK     16
#define AF_ROUTE       AF_NETLINK /* Alias to emulate 4.4BSD */
#define AF_PACKET      17         /* Packet family */
#define AF_ASH         18         /* Ash */
#define AF_ECONET      19         /* Acorn Econet */
#define AF_ATMSVC      20         /* ATM SVCs */
#define AF_RDS         21         /* RDS sockets */
#define AF_SNA         22         /* Linux SNA Project (nutters!) */
#define AF_IRDA        23         /* IRDA sockets */
#define AF_PPPOX       24         /* PPPoX sockets */
#define AF_WANPIPE     25         /* Wanpipe API Sockets */
#define AF_LLC         26         /* Linux LLC */
#define AF_IB          27         /* Native InfiniBand address */
#define AF_MPLS        28         /* MPLS */
#define AF_CAN         29         /* Controller Area Network */
#define AF_TIPC        30         /* TIPC sockets */
#define AF_BLUETOOTH   31         /* Bluetooth sockets */
#define AF_IUCV        32         /* IUCV sockets */
#define AF_RXRPC       33         /* RxRPC sockets */
#define AF_ISDN        34         /* mISDN sockets */
#define AF_PHONET      35         /* Phonet sockets */
#define AF_IEEE802154  36         /* IEEE802154 sockets */
#define AF_CAIF        37         /* CAIF sockets */
#define AF_ALG         38         /* Algorithm sockets */
#define AF_NFC         39         /* NFC sockets */
#define AF_VSOCK       40         /* vSockets */
#define AF_KCM         41         /* Kernel Connection Multiplexor */
#define AF_QIPCRTR     42         /* Qualcomm IPC Router */
#define AF_SMC         43         /* smc sockets: reserve number for PF_SMC protocol family that reuses AF_INET address family */

#define VM_NONE      0x00000000
#define VM_READ      0x00000001
#define VM_WRITE     0x00000002
#define VM_EXEC      0x00000004
#define VM_SHARED    0x00000008

#define TC_ACT_UNSPEC    (-1)
#define TC_ACT_OK           0
#define TC_ACT_RECLASSIFY   1
#define TC_ACT_SHOT         2
#define TC_ACT_PIPE         3
#define TC_ACT_STOLEN       4
#define TC_ACT_QUEUED       5
#define TC_ACT_REPEAT       6
#define TC_ACT_REDIRECT     7

#define ETH_P_IP    0x0800
#define ETH_P_IPV6  0x86DD

#define s6_addr         in6_u.u6_addr8
#define s6_addr16       in6_u.u6_addr16
#define s6_addr32       in6_u.u6_addr32

#define __user

static inline bool ipv6_addr_any(const struct in6_addr *a)
{
    return (a->in6_u.u6_addr32[0] | a->in6_u.u6_addr32[1] | a->in6_u.u6_addr32[2] | a->in6_u.u6_addr32[3]) == 0;
}

static inline struct inet_sock *inet_sk(const struct sock *sk)
{
	return (struct inet_sock *)sk;
}

#endif