#ifndef __COMMON_BUFFER_H__
#define __COMMON_BUFFER_H__

#include <vmlinux.h>

#include <common/context.h>
#include <common/hash.h>
#include <common/network.h>

// PROTOTYPES

statfunc buf_t *get_buf(int);
statfunc data_filter_key_t *get_string_data_filter_buf(int);
statfunc data_filter_lpm_key_t *get_string_data_filter_lpm_buf(int);
statfunc int reverse_string(char *, char *, int, int);
statfunc int save_to_submit_buf(args_buffer_t *, void *, u32, u8);
statfunc int save_bytes_to_buf(args_buffer_t *, void *, u32, u8);
statfunc int save_str_to_buf(args_buffer_t *, void *, u8);
statfunc int add_u64_elements_to_buf(args_buffer_t *, const u64 __user *, int, volatile u32);
statfunc int save_u64_arr_to_buf(args_buffer_t *, const u64 __user *, int, u8);
statfunc int save_str_arr_to_buf(args_buffer_t *, const char __user *const __user *, u8);
statfunc int save_args_str_arr_to_buf(args_buffer_t *, const char *, const char *, int, u8);
statfunc int save_sockaddr_to_buf(args_buffer_t *, struct socket *, u8);
statfunc int save_args_to_submit_buf(event_data_t *, args_t *);
statfunc int events_perf_submit(program_data_t *, long);
statfunc int signal_perf_submit(void *, controlplane_signal_t *);

// FUNCTIONS

statfunc buf_t *get_buf(int idx)
{
    return bpf_map_lookup_elem(&bufs, &idx);
}

statfunc data_filter_key_t *get_string_data_filter_buf(int idx)
{
    return bpf_map_lookup_elem(&data_filter_bufs, &idx);
}

statfunc data_filter_lpm_key_t *get_string_data_filter_lpm_buf(int idx)
{
    return bpf_map_lookup_elem(&data_filter_lpm_bufs, &idx);
}

// biggest elem to be saved with 'save_to_submit_buf' should be defined here:
#define MAX_ELEMENT_SIZE bpf_core_type_size(struct sockaddr_un)

statfunc int reverse_string(char *dst, char *src, int src_off, int len)
{
    uint i;

    if (!dst || !src || src_off < 0 || len <= 0) {
        return 0;
    }

    // don't count null-termination since we will force it at the end
    len = (len - 1) & MAX_DATA_FILTER_STR_SIZE_MASK;

    // Copy with safe bounds checking
    for (i = 0; i < len; i++) {
        // This line is necessary to satisfy the eBPF Verifier
        if (i >= MAX_DATA_FILTER_STR_SIZE)
            break;

        u32 idx = src_off + len - 1 - i;

        // Ensure the calculated index is within bounds
        if (idx >= ARGS_BUF_SIZE)
            return 0;

        dst[i] = src[idx];
    }

    // Force null-termination at the end
    dst[i] = '\0';

    // Characters copied with null-termination
    return i + 1;
}

statfunc int save_to_submit_buf(args_buffer_t *buf, void *ptr, u32 size, u8 index)
{
    // Data saved to submit buf: [index][ ... buffer[size] ... ]

    if (size == 0)
        return 0;

    barrier();
    if (buf->offset > ARGS_BUF_SIZE - 1)
        return 0;

    // Save argument index
    buf->args[buf->offset] = index;

    // Satisfy verifier
    if (buf->offset > ARGS_BUF_SIZE - (MAX_ELEMENT_SIZE + 1))
        return 0;

    // Read into buffer
    if (bpf_probe_read(&(buf->args[buf->offset + 1]), size, ptr) == 0) {
        // We update offset only if all writes were successful
        buf->offset += size + 1;
        buf->argnum++;
        return 1;
    }

    return 0;
}

statfunc int save_bytes_to_buf(args_buffer_t *buf, void *ptr, u32 size, u8 index)
{
    // Data saved to submit buf: [index][size][ ... bytes ... ]

    if (size == 0)
        return 0;

    if (buf->offset > ARGS_BUF_SIZE - 1)
        return 0;

    // Save argument index
    buf->args[buf->offset] = index;

    if (buf->offset > ARGS_BUF_SIZE - (sizeof(int) + 1))
        return 0;

    // Save size to buffer
    if (bpf_probe_read(&(buf->args[buf->offset + 1]), sizeof(int), &size) != 0) {
        return 0;
    }

    if (buf->offset > ARGS_BUF_SIZE - (MAX_BYTES_ARR_SIZE + 1 + sizeof(int)))
        return 0;

    // Read bytes into buffer
    if (bpf_probe_read(&(buf->args[buf->offset + 1 + sizeof(int)]),
                       size & (MAX_BYTES_ARR_SIZE - 1),
                       ptr) == 0) {
        // We update offset only if all writes were successful
        buf->offset += size + 1 + sizeof(int);
        buf->argnum++;
        return 1;
    }

    return 0;
}

statfunc int load_str_from_buf(args_buffer_t *buf, char *str, u8 index, enum str_filter_type_e type)
{
    u16 offset;
    u32 size;

    // skip if index is not in buffer
    if (index > buf->argnum)
        return 0;

    offset = buf->args_offset[index];

    if (offset == INVALID_ARG_OFFSET)
        return 0;

    // Ensure there is enough space for read index (u8)
    if ((offset + sizeof(u8)) > ARGS_BUF_SIZE)
        return 0;

    // Skip index
    offset += sizeof(u8);

    // Ensure there is enough space for read size (u32)
    if ((offset + sizeof(u32)) > ARGS_BUF_SIZE)
        return 0;

    // Copy the size
    __builtin_memcpy(&size, &(buf->args[offset]), sizeof(u32));

    // Skip size
    offset += sizeof(u32);

    // Adjust size and offset based on filter type
    switch (type) {
        case FILTER_TYPE_EXACT:
            if (size > MAX_DATA_FILTER_STR_SIZE)
                return 0;
            break;

        case FILTER_TYPE_PREFIX:
            size = size > MAX_DATA_FILTER_STR_SIZE ? MAX_DATA_FILTER_STR_SIZE : size;
            break;

        case FILTER_TYPE_SUFFIX:
            if (size > MAX_DATA_FILTER_STR_SIZE) {
                offset += size - MAX_DATA_FILTER_STR_SIZE;
                size = MAX_DATA_FILTER_STR_SIZE;
            }
            break;

        default:
            // Invalid filter type
            return 0;
    }

    // Ensure there is enough space to read the string
    if ((offset + size) > ARGS_BUF_SIZE)
        return 0;

    // Load string in reverse order if suffix type
    if (type == FILTER_TYPE_SUFFIX)
        size = reverse_string(str, buf->args, offset, size);
    else
        size = bpf_probe_read_kernel_str(str, size, &(buf->args[offset]));

    return size;
}

statfunc int save_str_to_buf(args_buffer_t *buf, void *ptr, u8 index)
{
    // Data saved to submit buf: [index][size][ ... string ... ]

    if (buf->offset > ARGS_BUF_SIZE - 1)
        return 0;

    // Save argument index
    buf->args[buf->offset] = index;

    // Save offset at the specified index
    buf->args_offset[index] = buf->offset;

    // Satisfy verifier for probe read
    if (buf->offset > ARGS_BUF_SIZE - (MAX_STRING_SIZE + 1 + sizeof(int)))
        return 0;

    // Read into buffer
    int sz = bpf_probe_read_str(&(buf->args[buf->offset + 1 + sizeof(int)]), MAX_STRING_SIZE, ptr);
    if (sz > 0) {
        barrier();
        // Satisfy verifier for probe read
        if (buf->offset > ARGS_BUF_SIZE - (MAX_STRING_SIZE + 1 + sizeof(int)))
            return 0;

        __builtin_memcpy(&(buf->args[buf->offset + 1]), &sz, sizeof(int));
        buf->offset += sz + sizeof(int) + 1;
        buf->argnum++;
        return 1;
    }

    return 0;
}

statfunc int
add_u64_elements_to_buf(args_buffer_t *buf, const u64 __user *ptr, int len, volatile u32 count_off)
{
    // save count_off into a new variable to avoid verifier errors
    u32 off = count_off;
    u8 elem_num = 0;
#pragma unroll
    for (int i = 0; i < len; i++) {
        void *addr = &(buf->args[buf->offset]);
        if (buf->offset > ARGS_BUF_SIZE - sizeof(u64))
            // not enough space - return
            goto out;
        if (bpf_probe_read(addr, sizeof(u64), (void *) &ptr[i]) != 0)
            goto out;
        elem_num++;
        buf->offset += sizeof(u64);
    }
out:
    // save number of elements in the array
    if (off > (ARGS_BUF_SIZE - 1))
        return 0;

    u8 current_elem_num = buf->args[off];
    buf->args[off] = current_elem_num + elem_num;

    return 1;
}

statfunc int save_u64_arr_to_buf(args_buffer_t *buf, const u64 *ptr, int len, u8 index)
{
    // Data saved to submit buf: [index][u16 count][u64 1][u64 2][u64 3]...
    u16 restricted_len = (u16) len;
    u32 total_size = sizeof(u64) * restricted_len;

    if (buf->offset > ARGS_BUF_SIZE - 1)
        return 0;

    // Save argument index
    buf->args[buf->offset] = index;

    // Save number of elements
    if (buf->offset + sizeof(index) > ARGS_BUF_SIZE - sizeof(restricted_len))
        return 0;
    __builtin_memcpy(
        &(buf->args[buf->offset + sizeof(index)]), &restricted_len, sizeof(restricted_len));

    if ((buf->offset + sizeof(index) + sizeof(restricted_len) > ARGS_BUF_SIZE - MAX_BYTES_ARR_SIZE))
        return 0;

    if (bpf_probe_read(&(buf->args[buf->offset + sizeof(index) + sizeof(restricted_len)]),
                       total_size & (MAX_BYTES_ARR_SIZE - 1),
                       (void *) ptr) != 0)
        return 0;

    buf->argnum++;
    buf->offset += sizeof(index) + sizeof(restricted_len) + total_size;

    return 1;
}

statfunc int save_str_arr_to_buf(args_buffer_t *buf, const char __user *const __user *ptr, u8 index)
{
    // Data saved to submit buf: [index][string count][str1 size][str1][str2 size][str2]...

    u8 elem_num = 0;

    if (buf->offset > ARGS_BUF_SIZE - 1)
        return 0;

    // Save argument index
    buf->args[buf->offset] = index;

    // Save space for number of elements (1 byte)
    u32 orig_off = buf->offset + 1;
    buf->offset += 2;

#pragma unroll
    for (int i = 0; i < MAX_STR_ARR_ELEM; i++) {
        const char *argp = NULL;
        bpf_probe_read(&argp, sizeof(argp), &ptr[i]);
        if (!argp)
            goto out;

        if (buf->offset > ARGS_BUF_SIZE - MAX_STRING_SIZE - sizeof(int))
            // not enough space - return
            goto out;

        // Read into buffer
        int sz = bpf_probe_read_str(&(buf->args[buf->offset + sizeof(int)]), MAX_STRING_SIZE, argp);
        if (sz > 0) {
            if (buf->offset > ARGS_BUF_SIZE - sizeof(int))
                // Satisfy validator
                goto out;
            bpf_probe_read(&(buf->args[buf->offset]), sizeof(int), &sz);
            buf->offset += sz + sizeof(int);
            elem_num++;
            continue;
        } else {
            goto out;
        }
    }
    // handle truncated argument list
    char ellipsis[] = "...";
    if (buf->offset > ARGS_BUF_SIZE - MAX_STRING_SIZE - sizeof(int))
        // not enough space - return
        goto out;

    // Read into buffer
    int sz = bpf_probe_read_str(&(buf->args[buf->offset + sizeof(int)]), MAX_STRING_SIZE, ellipsis);
    if (sz > 0) {
        if (buf->offset > ARGS_BUF_SIZE - sizeof(int))
            // Satisfy validator
            goto out;
        bpf_probe_read(&(buf->args[buf->offset]), sizeof(int), &sz);
        buf->offset += sz + sizeof(int);
        elem_num++;
    }
out:
    // save number of elements in the array
    if (orig_off > ARGS_BUF_SIZE - 1)
        return 0;
    buf->args[orig_off] = elem_num;
    buf->argnum++;
    return 1;
}

#define MAX_ARR_LEN 8192

statfunc int save_args_str_arr_to_buf(
    args_buffer_t *buf, const char *start, const char *end, int elem_num, u8 index)
{
    // Data saved to submit buf: [index][len][arg_len][arg #][null delimited string array]
    // Note: This helper saves null (0x00) delimited string array into buf

    if (start >= end)
        return 0;

    int len = end - start;
    if (len > (MAX_ARR_LEN - 1))
        len = MAX_ARR_LEN - 1;

    // Save argument index
    if (buf->offset > ARGS_BUF_SIZE - 1)
        return 0;
    buf->args[buf->offset] = index;

    // Satisfy validator for probe read
    if ((buf->offset + 1) > ARGS_BUF_SIZE - sizeof(int))
        return 0;

    // Save array length
    bpf_probe_read(&(buf->args[buf->offset + 1]), sizeof(int), &len);

    // Satisfy validator for probe read
    if ((buf->offset + 5) > ARGS_BUF_SIZE - sizeof(int))
        return 0;

    // Save number of arguments
    bpf_probe_read(&(buf->args[buf->offset + 5]), sizeof(int), &elem_num);

    // Satisfy validator for probe read
    if ((buf->offset + 9) > ARGS_BUF_SIZE - MAX_ARR_LEN)
        return 0;

    // Read into buffer
    if (bpf_probe_read(&(buf->args[buf->offset + 9]), len & (MAX_ARR_LEN - 1), start) == 0) {
        // We update offset only if all writes were successful
        buf->offset += len + 9;
        buf->argnum++;
        return 1;
    }

    return 0;
}

statfunc int save_sockaddr_to_buf(args_buffer_t *buf, struct socket *sock, u8 index)
{
    struct sock *sk = get_socket_sock(sock);

    u16 family = get_sock_family(sk);
    if ((family != AF_INET) && (family != AF_INET6) && (family != AF_UNIX)) {
        return 0;
    }

    if (family == AF_INET) {
        net_conn_v4_t net_details = {};
        struct sockaddr_in local;

        get_network_details_from_sock_v4(sk, &net_details, 0);
        get_local_sockaddr_in_from_network_details(&local, &net_details, family);

        save_to_submit_buf(buf, (void *) &local, bpf_core_type_size(struct sockaddr_in), index);
    } else if (family == AF_INET6) {
        net_conn_v6_t net_details = {};
        struct sockaddr_in6 local;

        get_network_details_from_sock_v6(sk, &net_details, 0);
        get_local_sockaddr_in6_from_network_details(&local, &net_details, family);

        save_to_submit_buf(buf, (void *) &local, bpf_core_type_size(struct sockaddr_in6), index);
    } else if (family == AF_UNIX) {
        struct unix_sock *unix_sk = (struct unix_sock *) sk;
        struct sockaddr_un sockaddr = get_unix_sock_addr(unix_sk);
        save_to_submit_buf(buf, (void *) &sockaddr, bpf_core_type_size(struct sockaddr_un), index);
    }
    return 0;
}

#define DEC_ARG(n, enc_arg) ((enc_arg >> (8 * n)) & 0xFF)

#define BITMASK_INDIRECT_VALUE_TYPES                                                               \
    ((u64) 1 << STR_T | (u64) 1 << SOCKADDR_T | (u64) 1 << INT_ARR_2_T | (u64) 1 << TIMESPEC_T)

#define BITMASK_COMMON_TYPES                                                                       \
    ((u64) 1 << INT_T | (u64) 1 << UINT_T | (u64) 1 << LONG_T | (u64) 1 << ULONG_T |               \
     (u64) 1 << OFF_T_T | (u64) 1 << MODE_T_T | (u64) 1 << DEV_T_T | (u64) 1 << SIZE_T_T |         \
     (u64) 1 << POINTER_T | (u64) 1 << STR_ARR_T | (u64) 1 << BYTES_T | (u64) 1 << U16_T |         \
     (u64) 1 << CRED_T | (u64) 1 << UINT64_ARR_T | (u64) 1 << U8_T)

#define ARG_TYPE_MAX_ARRAY (u8) TIMESPEC_T // last element defined in argument_type_e

// Ensure that only values that can be held by an u8 are assigned to sizes.
// If the size is greater than 255, assign 0 (making it evident) and handle it as a special case.
static u8 type_size_table[ARG_TYPE_MAX_ARRAY + 1] = {
    [NONE_T] = 0,
    [INT_T] = sizeof(int),
    [UINT_T] = sizeof(unsigned int),
    [LONG_T] = sizeof(long),
    [ULONG_T] = sizeof(unsigned long),
    [OFF_T_T] = sizeof(off_t),
    [MODE_T_T] = sizeof(mode_t),
    [DEV_T_T] = sizeof(dev_t),
    [SIZE_T_T] = sizeof(size_t),
    [POINTER_T] = sizeof(void *),
    [STR_T] = 0,
    [STR_ARR_T] = 0,
    [SOCKADDR_T] = sizeof(short),
    [BYTES_T] = 0,
    [U16_T] = sizeof(u16),
    [CRED_T] = sizeof(struct cred),
    [INT_ARR_2_T] = sizeof(int[2]),
    [UINT64_ARR_T] = 0,
    [U8_T] = sizeof(u8),
    [TIMESPEC_T] = 0,
};

statfunc int save_args_to_submit_buf(event_data_t *event, args_t *args)
{
    u8 i;
    u8 type;
    u64 type_mask;
    u32 rc = 0;
    u32 arg_num = 0;
    u32 size;
    void *arg;
    short family;

    if (unlikely(event->config.field_types == 0))
        return 0;

#pragma unroll
    for (i = 0; i < 6; i++) {
        type = DEC_ARG(i, event->config.field_types);

        // bounds check for the verifier
        if (unlikely(type > ARG_TYPE_MAX_ARRAY))
            continue; // skip types not defined in the type_size_table
        size = type_size_table[type];

        if (type == NONE_T)
            continue;
        type_mask = (u64) 1 << type; // type value must be < 64

        if (BITMASK_INDIRECT_VALUE_TYPES & type_mask)
            arg = (void *) args->args[i];
        else
            arg = (void *) &args->args[i];

        // handle common types
        if (BITMASK_COMMON_TYPES & type_mask)
            goto save_arg;

        // handle special types
        switch (type) {
            case STR_T:
                rc = save_str_to_buf(&(event->args_buf), arg, i);
                goto check_rc;
            case SOCKADDR_T: {
                // default size from the type_size_table
                if (!arg) {
                    family = 0;
                    arg = (void *) &family;
                    goto save_arg;
                }

                bpf_probe_read(&family, sizeof(short), arg);
                switch (family) {
                    case AF_UNIX:
                        size = bpf_core_type_size(struct sockaddr_un);
                        break;
                    case AF_INET:
                        size = bpf_core_type_size(struct sockaddr_in);
                        break;
                    case AF_INET6:
                        size = bpf_core_type_size(struct sockaddr_in6);
                        break;
                }
                goto save_arg;
            }
            case TIMESPEC_T:
                size = bpf_core_type_size(struct __kernel_timespec);
                goto save_arg;
            default:
                goto save_arg;
        }

    save_arg:
        rc = save_to_submit_buf(&(event->args_buf), arg, size, i);

    check_rc:
        if (rc > 0) {
            arg_num++;
            rc = 0;
        }
    }

    return arg_num;
}

#ifdef METRICS
struct event_stats_values {
    u64 attempts;
    u64 failures;
};

typedef struct event_stats_values event_stats_values_t;

struct events_stats {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, MAX_EVENT_ID);
    __type(key, u32); // eventid
    __type(value, event_stats_values_t);
} events_stats SEC(".maps");

typedef struct events_stats events_stats_t;
#endif

statfunc int events_perf_submit(program_data_t *p, long ret)
{
    p->event->context.retval = ret;

    // enrich event with task context
    init_task_context(&p->event->context.task, p->event->task, p->config->options);
    // keep task_info updated
    bpf_probe_read_kernel(&p->task_info->context, sizeof(task_context_t), &p->event->context.task);

    u32 size = sizeof(event_context_t) + sizeof(u8) +
               p->event->args_buf.offset; // context + argnum + arg buffer size

    // inline bounds check to force compiler to use the register of size
    asm volatile("if %[size] < %[max_size] goto +1;\n"
                 "%[size] = %[max_size];\n"
                 :
                 : [size] "r"(size), [max_size] "i"(MAX_EVENT_SIZE));

    long perf_ret = bpf_perf_event_output(p->ctx, &events, BPF_F_CURRENT_CPU, p->event, size);

#ifdef METRICS
    // update event stats
    event_stats_values_t *evt_stat = bpf_map_lookup_elem(&events_stats, &p->event->context.eventid);
    if (unlikely(evt_stat == NULL))
        return perf_ret;

    __sync_fetch_and_add(&evt_stat->attempts, 1);
    if (perf_ret < 0)
        __sync_fetch_and_add(&evt_stat->failures, 1);
#endif

    return perf_ret;
}

statfunc int signal_perf_submit(void *ctx, controlplane_signal_t *sig)
{
    u32 size =
        sizeof(u32) + sizeof(u8) + sig->args_buf.offset; // signal id + argnum + arg buffer size

    // inline bounds check to force compiler to use the register of size
    asm volatile("if %[size] < %[max_size] goto +1;\n"
                 "%[size] = %[max_size];\n"
                 :
                 : [size] "r"(size), [max_size] "i"(MAX_SIGNAL_SIZE));

    return bpf_perf_event_output(ctx, &signals, BPF_F_CURRENT_CPU, sig, size);
}

#endif
