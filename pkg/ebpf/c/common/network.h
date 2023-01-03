#ifndef __TRACEE_NETWORK_H__
#define __TRACEE_NETWORK_H__

#include <bpf/bpf_helpers.h>
#include "common/common.h"
#include "types.h"
#include "maps.h"

static __always_inline u32 get_inet_rcv_saddr(struct inet_sock *inet)
{
    return READ_KERN(inet->inet_rcv_saddr);
}

static __always_inline u32 get_inet_saddr(struct inet_sock *inet)
{
    return READ_KERN(inet->inet_saddr);
}

static __always_inline u32 get_inet_daddr(struct inet_sock *inet)
{
    return READ_KERN(inet->inet_daddr);
}

static __always_inline u16 get_inet_sport(struct inet_sock *inet)
{
    return READ_KERN(inet->inet_sport);
}

static __always_inline u16 get_inet_num(struct inet_sock *inet)
{
    return READ_KERN(inet->inet_num);
}

static __always_inline u16 get_inet_dport(struct inet_sock *inet)
{
    return READ_KERN(inet->inet_dport);
}

static __always_inline struct sock *get_socket_sock(struct socket *socket)
{
    return READ_KERN(socket->sk);
}

static __always_inline u16 get_sock_family(struct sock *sock)
{
    return READ_KERN(sock->sk_family);
}

static __always_inline u16 get_sock_protocol(struct sock *sock)
{
    u16 protocol = 0;

#ifndef CORE
    #if (LINUX_VERSION_CODE < KERNEL_VERSION(5, 6, 0))
    // kernel 4.18-5.5: sk_protocol bit-field: use sk_gso_max_segs field and go
    // back 24 bits to reach sk_protocol field index.
    bpf_probe_read(&protocol, 1, (void *) (&sock->sk_gso_max_segs) - 3);
    #else
    // kernel 5.6
    protocol = READ_KERN(sock->sk_protocol);
    #endif
#else // CORE
    // commit bf9765145b85 ("sock: Make sk_protocol a 16-bit value")
    struct sock___old *check = NULL;
    if (bpf_core_field_exists(check->__sk_flags_offset)) {
        check = (struct sock___old *) sock;
        bpf_core_read(&protocol, 1, (void *) (&check->sk_gso_max_segs) - 3);
    } else {
        protocol = READ_KERN(sock->sk_protocol);
    }
#endif

    return protocol;
}

static __always_inline u16 get_sockaddr_family(struct sockaddr *address)
{
    return READ_KERN(address->sa_family);
}

static __always_inline struct in6_addr get_sock_v6_rcv_saddr(struct sock *sock)
{
    return READ_KERN(sock->sk_v6_rcv_saddr);
}

static __always_inline struct in6_addr get_ipv6_pinfo_saddr(struct ipv6_pinfo *np)
{
    return READ_KERN(np->saddr);
}

static __always_inline struct in6_addr get_sock_v6_daddr(struct sock *sock)
{
    return READ_KERN(sock->sk_v6_daddr);
}

static __always_inline volatile unsigned char get_sock_state(struct sock *sock)
{
    volatile unsigned char sk_state_own_impl;
    bpf_probe_read(
        (void *) &sk_state_own_impl, sizeof(sk_state_own_impl), (const void *) &sock->sk_state);
    return sk_state_own_impl;
}

static __always_inline struct ipv6_pinfo *get_inet_pinet6(struct inet_sock *inet)
{
    struct ipv6_pinfo *pinet6_own_impl;
    bpf_probe_read(&pinet6_own_impl, sizeof(pinet6_own_impl), &inet->pinet6);
    return pinet6_own_impl;
}

static __always_inline struct sockaddr_un get_unix_sock_addr(struct unix_sock *sock)
{
    struct unix_address *addr = READ_KERN(sock->addr);
    int len = READ_KERN(addr->len);
    struct sockaddr_un sockaddr = {};
    if (len <= sizeof(struct sockaddr_un)) {
        bpf_probe_read(&sockaddr, len, addr->name);
    }
    return sockaddr;
}

static __always_inline int
get_network_details_from_sock_v4(struct sock *sk, net_conn_v4_t *net_details, int peer)
{
    struct inet_sock *inet = inet_sk(sk);

    if (!peer) {
        net_details->local_address = get_inet_rcv_saddr(inet);
        net_details->local_port = bpf_ntohs(get_inet_num(inet));
        net_details->remote_address = get_inet_daddr(inet);
        net_details->remote_port = get_inet_dport(inet);
    } else {
        net_details->remote_address = get_inet_rcv_saddr(inet);
        net_details->remote_port = bpf_ntohs(get_inet_num(inet));
        net_details->local_address = get_inet_daddr(inet);
        net_details->local_port = get_inet_dport(inet);
    }

    return 0;
}

static __always_inline struct ipv6_pinfo *inet6_sk_own_impl(struct sock *__sk,
                                                            struct inet_sock *inet)
{
    volatile unsigned char sk_state_own_impl;
    sk_state_own_impl = get_sock_state(__sk);

    struct ipv6_pinfo *pinet6_own_impl;
    pinet6_own_impl = get_inet_pinet6(inet);

    bool sk_fullsock = (1 << sk_state_own_impl) & ~(TCPF_TIME_WAIT | TCPF_NEW_SYN_RECV);
    return sk_fullsock ? pinet6_own_impl : NULL;
}

static __always_inline int
get_network_details_from_sock_v6(struct sock *sk, net_conn_v6_t *net_details, int peer)
{
    // inspired by 'inet6_getname(struct socket *sock, struct sockaddr *uaddr, int peer)'
    // reference: https://elixir.bootlin.com/linux/latest/source/net/ipv6/af_inet6.c#L509

    struct inet_sock *inet = inet_sk(sk);
    struct ipv6_pinfo *np = inet6_sk_own_impl(sk, inet);

    struct in6_addr addr = {};
    addr = get_sock_v6_rcv_saddr(sk);
    if (ipv6_addr_any(&addr)) {
        addr = get_ipv6_pinfo_saddr(np);
    }

    // the flowinfo field can be specified by the user to indicate a network flow. how it is used by
    // the kernel, or whether it is enforced to be unique is not so obvious.  getting this value is
    // only supported by the kernel for outgoing packets using the 'struct ipv6_pinfo'.  in any
    // case, leaving it with value of 0 won't affect our representation of network flows.
    net_details->flowinfo = 0;

    // the scope_id field can be specified by the user to indicate the network interface from which
    // to send a packet. this only applies for link-local addresses, and is used only by the local
    // kernel.  getting this value is done by using the 'ipv6_iface_scope_id(const struct in6_addr
    // *addr, int iface)' function.  in any case, leaving it with value of 0 won't affect our
    // representation of network flows.
    net_details->scope_id = 0;

    if (peer) {
        net_details->local_address = get_sock_v6_daddr(sk);
        net_details->local_port = get_inet_dport(inet);
        net_details->remote_address = addr;
        net_details->remote_port = get_inet_sport(inet);
    } else {
        net_details->local_address = addr;
        net_details->local_port = get_inet_sport(inet);
        net_details->remote_address = get_sock_v6_daddr(sk);
        net_details->remote_port = get_inet_dport(inet);
    }

    return 0;
}

static __always_inline int get_local_sockaddr_in_from_network_details(struct sockaddr_in *addr,
                                                                      net_conn_v4_t *net_details,
                                                                      u16 family)
{
    addr->sin_family = family;
    addr->sin_port = net_details->local_port;
    addr->sin_addr.s_addr = net_details->local_address;

    return 0;
}

static __always_inline int get_remote_sockaddr_in_from_network_details(struct sockaddr_in *addr,
                                                                       net_conn_v4_t *net_details,
                                                                       u16 family)
{
    addr->sin_family = family;
    addr->sin_port = net_details->remote_port;
    addr->sin_addr.s_addr = net_details->remote_address;

    return 0;
}

static __always_inline int get_local_sockaddr_in6_from_network_details(struct sockaddr_in6 *addr,
                                                                       net_conn_v6_t *net_details,
                                                                       u16 family)
{
    addr->sin6_family = family;
    addr->sin6_port = net_details->local_port;
    addr->sin6_flowinfo = net_details->flowinfo;
    addr->sin6_addr = net_details->local_address;
    addr->sin6_scope_id = net_details->scope_id;

    return 0;
}

static __always_inline int get_remote_sockaddr_in6_from_network_details(struct sockaddr_in6 *addr,
                                                                        net_conn_v6_t *net_details,
                                                                        u16 family)
{
    addr->sin6_family = family;
    addr->sin6_port = net_details->remote_port;
    addr->sin6_flowinfo = net_details->flowinfo;
    addr->sin6_addr = net_details->remote_address;
    addr->sin6_scope_id = net_details->scope_id;

    return 0;
}

static __always_inline int get_local_net_id_from_network_details_v4(struct sock *sk,
                                                                    net_id_t *connect_id,
                                                                    net_conn_v4_t *net_details,
                                                                    u16 family)
{
    connect_id->address.s6_addr32[3] = net_details->local_address;
    connect_id->address.s6_addr16[5] = 0xffff;
    connect_id->port = net_details->local_port;
    connect_id->protocol = get_sock_protocol(sk);

    return 0;
}

static __always_inline int get_local_net_id_from_network_details_v6(struct sock *sk,
                                                                    net_id_t *connect_id,
                                                                    net_conn_v6_t *net_details,
                                                                    u16 family)
{
    connect_id->address = net_details->local_address;
    connect_id->port = net_details->local_port;
    connect_id->protocol = get_sock_protocol(sk);

    return 0;
}

#endif