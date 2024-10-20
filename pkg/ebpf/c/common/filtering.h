#ifndef __COMMON_FILTERING_H__
#define __COMMON_FILTERING_H__

#include <vmlinux.h>

#include <maps.h>
#include <common/logging.h>
#include <common/task.h>
#include <common/common.h>

// PROTOTYPES

statfunc void *get_filter_map(void *, u16);
statfunc u64 uint_filter_range_matches(u64, void *, u64, u64, u64);
statfunc u64 binary_filter_matches(u64, void *, proc_info_t *);
statfunc u64 equality_filter_matches(u64, void *, void *);
statfunc u64 bool_filter_matches(u64, bool);
statfunc u64 match_scope_filters(program_data_t *);
statfunc u64 match_data_filters(program_data_t *, u8);
statfunc bool evaluate_scope_filters(program_data_t *);
statfunc bool evaluate_data_filters(program_data_t *, u8);
statfunc bool event_is_selected(u32, u16);
statfunc bool policies_matched(event_data_t *);

// CONSTANTS

#define FILTER_UID_ENABLED       (1 << 0)
#define FILTER_UID_OUT           (1 << 1)
#define FILTER_MNT_NS_ENABLED    (1 << 2)
#define FILTER_MNT_NS_OUT        (1 << 3)
#define FILTER_PID_NS_ENABLED    (1 << 4)
#define FILTER_PID_NS_OUT        (1 << 5)
#define FILTER_UTS_NS_ENABLED    (1 << 6)
#define FILTER_UTS_NS_OUT        (1 << 7)
#define FILTER_COMM_ENABLED      (1 << 8)
#define FILTER_COMM_OUT          (1 << 9)
#define FILTER_PID_ENABLED       (1 << 10)
#define FILTER_PID_OUT           (1 << 11)
#define FILTER_CONT_ENABLED      (1 << 12)
#define FILTER_CONT_OUT          (1 << 13)
#define FILTER_FOLLOW_ENABLED    (1 << 14)
#define FILTER_NEW_PID_ENABLED   (1 << 15)
#define FILTER_NEW_PID_OUT       (1 << 16)
#define FILTER_NEW_CONT_ENABLED  (1 << 17)
#define FILTER_NEW_CONT_OUT      (1 << 18)
#define FILTER_PROC_TREE_ENABLED (1 << 19)
#define FILTER_PROC_TREE_OUT     (1 << 20)
#define FILTER_CGROUP_ID_ENABLED (1 << 21)
#define FILTER_CGROUP_ID_OUT     (1 << 22)
#define FILTER_BIN_PATH_ENABLED  (1 << 23)
#define FILTER_BIN_PATH_OUT      (1 << 24)

#define FILTER_MAX_NOT_SET 0
#define FILTER_MIN_NOT_SET ULLONG_MAX

// FUNCTIONS

// get_filter_map returns the filter map for the given version and outer map
statfunc void *get_filter_map(void *outer_map, u16 version)
{
    return bpf_map_lookup_elem(outer_map, &version);
}

statfunc u64
uint_filter_range_matches(u64 filter_out_scopes, void *filter_map, u64 value, u64 max, u64 min)
{
    // check equality_filter_matches() for more info

    u64 equal_in_scopes = 0;
    u64 equality_set_in_scopes = 0;

    if (filter_map) {
        eq_t *equality = bpf_map_lookup_elem(filter_map, &value);
        if (equality != NULL) {
            equal_in_scopes = equality->equal_in_scopes;
            equality_set_in_scopes = equality->equality_set_in_scopes;
        }
    }

    if ((max != FILTER_MAX_NOT_SET) && (value >= max))
        return equal_in_scopes;

    if ((min != FILTER_MIN_NOT_SET) && (value <= min))
        return equal_in_scopes;

    return equal_in_scopes | (filter_out_scopes & ~equality_set_in_scopes);
}

statfunc u64 binary_filter_matches(u64 filter_out_scopes, void *filter_map, proc_info_t *proc_info)
{
    // check equality_filter_matches() for more info

    u64 equal_in_scopes = 0;
    u64 equality_set_in_scopes = 0;

    if (filter_map) {
        eq_t *equality = bpf_map_lookup_elem(filter_map, proc_info->binary.path);
        if (equality == NULL) {
            // lookup by binary path and mount namespace
            equality = bpf_map_lookup_elem(filter_map, &proc_info->binary);
        }
        if (equality != NULL) {
            equal_in_scopes = equality->equal_in_scopes;
            equality_set_in_scopes = equality->equality_set_in_scopes;
        }
    }

    return equal_in_scopes | (filter_out_scopes & ~equality_set_in_scopes);
}

statfunc u64 equality_filter_matches(u64 filter_out_scopes, void *filter_map, void *key)
{
    // check compute_scopes() for initial info
    //
    //   policy 2: comm=who
    //   policy 3: comm=ping
    //   policy 4: comm!=who
    //
    // filter_out_scopes = 0000 1000, since scope 4 has "not equal" for comm filter
    // filter_map        = comm_filter
    // key               = "who" | "ping"
    //
    // ---
    //
    // considering an event from "who" command
    //
    // equal_in_scopes   = 0000 0010, since scope 2 has "equal" for comm filter
    // equality_set_in_scopes = 0000 1010, since scope 2 and 4 are set for comm filter
    //
    // return            = equal_in_scopes | (filter_out_scopes & equality_set_in_scopes)
    //                     0000 0010 |
    //                     (0000 1000 & 1111 0101) -> 0000 0000
    //
    //                     0000 0010 |
    //                     0000 0000
    //                     ---------
    //                     0000 0010 = (scope 2 matched)
    //
    // considering an event from "ping" command
    //
    // equal_in_scopes   = 0000 0100, since scope 3 has "equal" for comm filter
    // equality_set_in_scopes = 0000 0100, since scope 3 is set for comm filter
    //
    // return            = equal_in_scopes | (filter_out_scopes & ~equality_set_in_scopes)
    //                     0000 0100 |
    //                     (0000 1000 & 0000 0100) -> 0000 0000
    //
    //                     0000 0100 |
    //                     0000 0000
    //                     ---------
    //                     0000 0100 = (scope 3 matched)

    u64 equal_in_scopes = 0;
    u64 equality_set_in_scopes = 0;

    if (filter_map) {
        eq_t *equality = bpf_map_lookup_elem(filter_map, key);
        if (equality != NULL) {
            equal_in_scopes = equality->equal_in_scopes;
            equality_set_in_scopes = equality->equality_set_in_scopes;
        }
    }
    // bpf_printk("filter_out_scopes       : 0x%llx\n", filter_out_scopes);
    // bpf_printk("equality_set_in_scopes  : 0x%llx\n", equality_set_in_scopes);
    // bpf_printk("equal_in_scopes         : 0x%llx\n", equal_in_scopes);
    u64 final = equal_in_scopes | (filter_out_scopes & ~equality_set_in_scopes);
    // bpf_printk("final                   : 0x%llx\n", final);

    return equal_in_scopes | (filter_out_scopes & ~equality_set_in_scopes);
}

statfunc u64 bool_filter_matches(u64 filter_out_scopes, bool val)
{
    // check compute_scopes() for initial info
    //
    //   policy 5: container=true
    //
    // considering an event from a container
    //
    //   filter_out_scopes = 0000 0000
    //   val               = true
    //   return            = 0000 0000 ^
    //                       1111 1111 <- ~0ULL
    //                       ---------
    //                       1111 1111
    //
    // considering an event not from a container
    //
    //   filter_out_scopes = 0000 0000
    //   val               = false
    //   return            = 0000 0000 ^
    //                       0000 0000
    //                       ---------
    //                       0000 0000

    return filter_out_scopes ^ (val ? ~0ULL : 0);
}

statfunc void reverse_string(char *dst, char *src, int len)
{
    uint i;

    // don't count null-termination since we will force it at the end
    len = (len - 1) & MAX_PATH_PREF_SIZE_MASK;

    // Copy with safe bounds checking
    for (i = 0; i < len; i++) {
        dst[i] = src[(len - 1 - i) & MAX_PATH_PREF_SIZE_MASK];
    }

    // Force null-termination at the end
    dst[i] = '\0';
}

statfunc u64 match_scope_filters(program_data_t *p)
{
    task_context_t *context = &p->event->context.task;

    // Don't monitor self
    if (p->config->tracee_pid == context->host_pid)
        return 0;

    proc_info_t *proc_info = p->proc_info;
    policies_config_t *policies_cfg = &p->event->policies_config;
    u64 res = ~0ULL;

    //
    // boolean filters (not using versioned filter maps)
    //

    if (policies_cfg->cont_filter_enabled_scopes) {
        bool is_container = false;
        u8 state = p->task_info->container_state;
        if (state == CONTAINER_STARTED || state == CONTAINER_EXISTED)
            is_container = true;
        u64 filter_out_scopes = policies_cfg->cont_filter_out_scopes;
        u64 mask = ~policies_cfg->cont_filter_enabled_scopes;

        // For scopes which has this filter disabled we want to set the matching bits using 'mask'
        res &= bool_filter_matches(filter_out_scopes, is_container) | mask;
    }

    if (policies_cfg->new_cont_filter_enabled_scopes) {
        bool is_new_container = false;
        if (p->task_info->container_state == CONTAINER_STARTED)
            is_new_container = true;
        u64 filter_out_scopes = policies_cfg->new_cont_filter_out_scopes;
        u64 mask = ~policies_cfg->new_cont_filter_enabled_scopes;

        res &= bool_filter_matches(filter_out_scopes, is_new_container) | mask;
    }

    if (policies_cfg->new_pid_filter_enabled_scopes) {
        u64 filter_out_scopes = policies_cfg->new_pid_filter_out_scopes;
        u64 mask = ~policies_cfg->new_pid_filter_enabled_scopes;

        res &= bool_filter_matches(filter_out_scopes, proc_info->new_proc) | mask;
    }

    //
    // equality filters (using versioned filter maps)
    //

    u16 version = p->event->context.policies_version;
    void *filter_map = NULL;

    if (policies_cfg->pid_filter_enabled_scopes) {
        u64 filter_out_scopes = policies_cfg->pid_filter_out_scopes;
        u64 mask = ~policies_cfg->pid_filter_enabled_scopes;
        u64 max = policies_cfg->pid_max;
        u64 min = policies_cfg->pid_min;

        filter_map = get_filter_map(&pid_filter_version, version);
        // the user might have given us a tid - check for it too
        res &=
            uint_filter_range_matches(filter_out_scopes, filter_map, context->host_pid, max, min) |
            uint_filter_range_matches(filter_out_scopes, filter_map, context->host_tid, max, min) |
            mask;
    }

    if (policies_cfg->uid_filter_enabled_scopes) {
        context->uid = bpf_get_current_uid_gid();
        u64 filter_out_scopes = policies_cfg->uid_filter_out_scopes;
        u64 mask = ~policies_cfg->uid_filter_enabled_scopes;
        u64 max = policies_cfg->uid_max;
        u64 min = policies_cfg->uid_min;

        filter_map = get_filter_map(&uid_filter_version, version);
        res &=
            uint_filter_range_matches(filter_out_scopes, filter_map, context->uid, max, min) | mask;
    }

    if (policies_cfg->mnt_ns_filter_enabled_scopes) {
        context->mnt_id = get_task_mnt_ns_id(p->event->task);
        u64 filter_out_scopes = policies_cfg->mnt_ns_filter_out_scopes;
        u64 mask = ~policies_cfg->mnt_ns_filter_enabled_scopes;

        filter_map = get_filter_map(&mnt_ns_filter_version, version);
        res &= equality_filter_matches(filter_out_scopes, filter_map, &context->mnt_id) | mask;
    }

    if (policies_cfg->pid_ns_filter_enabled_scopes) {
        context->pid_id = get_task_pid_ns_id(p->event->task);
        u64 filter_out_scopes = policies_cfg->pid_ns_filter_out_scopes;
        u64 mask = ~policies_cfg->pid_ns_filter_enabled_scopes;

        filter_map = get_filter_map(&pid_ns_filter_version, version);
        res &= equality_filter_matches(filter_out_scopes, filter_map, &context->pid_id) | mask;
    }

    if (policies_cfg->uts_ns_filter_enabled_scopes) {
        char *uts_name = get_task_uts_name(p->event->task);
        if (uts_name)
            bpf_probe_read_kernel_str(&context->uts_name, TASK_COMM_LEN, uts_name);
        u64 filter_out_scopes = policies_cfg->uts_ns_filter_out_scopes;
        u64 mask = ~policies_cfg->uts_ns_filter_enabled_scopes;

        filter_map = get_filter_map(&uts_ns_filter_version, version);
        res &= equality_filter_matches(filter_out_scopes, filter_map, &context->uts_name) | mask;
    }

    if (policies_cfg->comm_filter_enabled_scopes) {
        bpf_get_current_comm(&context->comm, sizeof(context->comm));
        u64 filter_out_scopes = policies_cfg->comm_filter_out_scopes;
        u64 mask = ~policies_cfg->comm_filter_enabled_scopes;

        filter_map = get_filter_map(&comm_filter_version, version);
        u64 res_eq = equality_filter_matches(filter_out_scopes, filter_map, &context->comm);
        bpf_printk(
            "[DBG] scope out:0x%llx mask:0x%llx res_eq:0x%llx", filter_out_scopes, mask, res_eq);
        u64 res_final = res & (res_eq | mask);
        bpf_printk("[DBG][scope] out:%llx mask:%llx res:%llx\n", filter_out_scopes, mask, res);
        bpf_printk("[DBG][scope] equality:%llx masked:%llx res_final:%llx\n",
                   res_eq,
                   res_eq | mask,
                   res_final);

        res &= res_eq | mask;
    }

    if (policies_cfg->cgroup_id_filter_enabled_scopes) {
        u32 cgroup_id_lsb = context->cgroup_id;
        u64 filter_out_scopes = policies_cfg->cgroup_id_filter_out_scopes;
        u64 mask = ~policies_cfg->cgroup_id_filter_enabled_scopes;

        filter_map = get_filter_map(&cgroup_id_filter_version, version);
        res &= equality_filter_matches(filter_out_scopes, filter_map, &cgroup_id_lsb) | mask;
    }

    if (policies_cfg->proc_tree_filter_enabled_scopes) {
        u64 filter_out_scopes = policies_cfg->proc_tree_filter_out_scopes;
        u64 mask = ~policies_cfg->proc_tree_filter_enabled_scopes;

        filter_map = get_filter_map(&process_tree_map_version, version);
        res &= equality_filter_matches(filter_out_scopes, filter_map, &context->host_pid) | mask;
    }

    if (policies_cfg->bin_path_filter_enabled_scopes) {
        u64 filter_out_scopes = policies_cfg->bin_path_filter_out_scopes;
        u64 mask = ~policies_cfg->bin_path_filter_enabled_scopes;

        filter_map = get_filter_map(&binary_filter_version, version);
        res &= binary_filter_matches(filter_out_scopes, filter_map, proc_info) | mask;
    }

    //
    // follow filter
    //

    if (policies_cfg->follow_filter_enabled_scopes) {
        // trace this proc anyway if follow was set by a scope
        res |= proc_info->follow_in_scopes & policies_cfg->follow_filter_enabled_scopes;
    }

    // Make sure only enabled scopes are set in the bitmask (other bits are invalid)
    return res & policies_cfg->enabled_scopes;
}

// Function to evaluate data filters based on the program data and index.
// Returns policies bitmap.
//
// Parameters:
// - program_data_t *p: Pointer to the program data structure.
// - u8 index: Index of the string data to be used as filter.
statfunc u64 match_data_filters(program_data_t *p, u8 index)
{
    policies_config_t *policies_cfg = &p->event->policies_config;
    u64 res = ~0ULL;

    u16 version = p->event->context.policies_version;
    void *filter_map = NULL;

    if (policies_cfg->exactly_enabled_data_filters || policies_cfg->prefix_enabled_data_filters ||
        policies_cfg->suffix_enabled_data_filters) {
        data_filter_lpm_key_t *key = get_data_filter_buf(0);

        if (key == NULL)
            return 0;

        // get event ID
        key->event_id = p->event->context.eventid;

        // get pathname based on index
        __builtin_memset(key->path, 0, sizeof(key->path));
        u32 len = load_str_from_buf(&p->event->args_buf, key->path, index);
        if (!len) {
            return 0;
        }

        // prefixlen need to be multipled by 8
        key->prefix_len = (len + sizeof(u32)) * 8;

        // Exactly match
        if (policies_cfg->exactly_enabled_data_filters) {
            // skip prefixlen by casting to obtain the key for exactly match
            data_filter_key_t *key_exactly = (data_filter_key_t *) &key->event_id;

            u64 filter_out_scopes = policies_cfg->exactly_out_data_filters;
            u64 mask = ~policies_cfg->exactly_enabled_data_filters;
            filter_map = get_filter_map(&data_filter_exactly_version, version);
            u64 final = equality_filter_matches(filter_out_scopes, filter_map, key_exactly);
            u64 final_mask = final | mask;

            // TODO: debug only - will be removed
            bpf_printk("[DBG][filter][exactly] [%d] \"%s\" res_old:0x%llx\n",
                       key->event_id,
                       key->path,
                       res);
            bpf_printk("[DBG][filter][exactly] mask:%llx equality:0x%llx masked:0x%llx\n",
                       mask,
                       final,
                       final_mask);
            bpf_printk("[DBG][filter][exactly] \"%s\" res_new:0x%llx out:0x%llx\n",
                       key->path,
                       (res & final_mask),
                       filter_out_scopes);

            // TODO: debug only - will be removed
            if (filter_map) {
                eq_t *equality = bpf_map_lookup_elem(filter_map, key_exactly);
                if (equality != NULL) {
                    u64 equal_in_scopes = equality->equal_in_scopes;
                    u64 equality_set_in_scopes = equality->equality_set_in_scopes;
                    bpf_printk("[DBG][exactly]FOUND ikf: %s ID:%d equality:%d\n",
                               key_exactly->path,
                               key_exactly->event_id,
                               equal_in_scopes);
                    bpf_printk("[DBG][exactly]FOUND ikf: %s res:%llx res_final:%llx\n",
                               key_exactly->path,
                               res,
                               res & final_mask);
                }
            }

            res &= final_mask;
        }

        // Prefix match
        if (policies_cfg->prefix_enabled_data_filters) {
            u64 filter_out_scopes = policies_cfg->prefix_out_data_filters;
            u64 mask = ~policies_cfg->prefix_enabled_data_filters;
            filter_map = get_filter_map(&data_filter_prefix_version, version);
            u64 final = equality_filter_matches(filter_out_scopes, filter_map, key);
            u64 final_mask = final | mask;

            // TODO: debug only - will be removed
            bpf_printk("[DBG][filter][prefix] [%d] \"%s\" res_old:0x%llx\n",
                       key->event_id,
                       key->path,
                       res);
            bpf_printk("[DBG][filter][prefix] mask:%llx equality:0x%llx masked:0x%llx\n",
                       mask,
                       final,
                       final_mask);
            bpf_printk("[DBG][filter][prefix] \"%s\" res_new:0x%llx out:0x%llx\n",
                       key->path,
                       (res & final_mask),
                       filter_out_scopes);

            // TODO: debug only - will be removed
            if (filter_map) {
                eq_t *equality = bpf_map_lookup_elem(filter_map, key);
                if (equality != NULL) {
                    u64 equal_in_scopes = equality->equal_in_scopes;
                    u64 equality_set_in_scopes = equality->equality_set_in_scopes;
                    bpf_printk("[DBG][prefix]FOUND ikf: %s ID:%d equality:%d\n",
                               key->path,
                               p->event->context.eventid,
                               equal_in_scopes);
                    bpf_printk("[DBG][prefix]FOUND ikf: %s res:%llx res_final:%llx\n",
                               key->path,
                               res,
                               res & final_mask);
                }
            }

            res &= final_mask;
        }

        // Suffix match
        if (policies_cfg->suffix_enabled_data_filters) {
            data_filter_lpm_key_t *key_suffix = get_data_filter_buf(1);

            if (key_suffix == NULL)
                return 0;

            // copy from prefix_len
            key_suffix->prefix_len = key->prefix_len;
            key_suffix->event_id = key->event_id;

            // reverse the string for suffix match
            __builtin_memset(key_suffix->path, 0, sizeof(key_suffix->path));
            reverse_string(key_suffix->path, key->path, len);

            u64 filter_out_scopes = policies_cfg->suffix_out_data_filters;
            u64 mask = ~policies_cfg->suffix_enabled_data_filters;
            filter_map = get_filter_map(&data_filter_suffix_version, version);
            u64 final = equality_filter_matches(filter_out_scopes, filter_map, key_suffix);
            u64 final_mask = final | mask;

            // TODO: debug only - will be removed
            bpf_printk("[DBG][suffix][reverse ][sz:%d][%s]", len, key_suffix->path);
            bpf_printk("[DBG][suffix][original][sz:%d][%s]", len, key->path);

            bpf_printk("[DBG][filter][suffix] [%d] \"%s\" res_old:0x%llx\n",
                       key->event_id,
                       key->path,
                       res);
            bpf_printk("[DBG][filter][suffix] mask:%llx equality:0x%llx masked:0x%llx\n",
                       mask,
                       final,
                       final_mask);
            bpf_printk("[DBG][filter][suffix] \"%s\" res_new:0x%llx out:0x%llx\n",
                       key->path,
                       (res & final_mask),
                       filter_out_scopes);

            // TODO: debug only - will be removed
            if (filter_map) {
                eq_t *equality = bpf_map_lookup_elem(filter_map, key_suffix);
                if (equality != NULL) {
                    u64 equal_in_scopes = equality->equal_in_scopes;
                    u64 equality_set_in_scopes = equality->equality_set_in_scopes;
                    bpf_printk("[DBG][suffix]FOUND ikf: %s ID:%d equality:%d\n",
                               key_suffix->path,
                               p->event->context.eventid,
                               equal_in_scopes);
                    bpf_printk("[DBG][suffix]FOUND ikf: %s res:%llx res_final:%llx\n",
                               key_suffix->path,
                               res,
                               res & final_mask);
                }
            }

            res &= final_mask;
        }
    }
    return res & policies_cfg->enabled_data_filters;
}

statfunc bool evaluate_scope_filters(program_data_t *p)
{
    u64 matched_scopes = match_scope_filters(p);
    bpf_printk("[DBG] matched_scopes                       : 0x%llx\n", matched_scopes);
    bpf_printk("[DBG] matched_policies                     : 0x%llx\n",
               p->event->context.matched_policies);
    bpf_printk("[DBG] matched_policies&matched_scopes      : 0x%llx\n",
               p->event->context.matched_policies & matched_scopes);
    p->event->context.matched_policies &= matched_scopes;
    return p->event->context.matched_policies != 0;
}

statfunc bool evaluate_data_filters(program_data_t *p, u8 index)
{
    u64 matched_data_filter = match_data_filters(p, index);
    bpf_printk("[DBG] matched_data_filter                  : 0x%llx\n", matched_data_filter);
    bpf_printk("[DBG] matched_policies                     : 0x%llx\n",
               p->event->context.matched_policies);
    bpf_printk("[DBG] matched_policies&matched_data_filter : 0x%llx\n",
               p->event->context.matched_policies & matched_data_filter);
    p->event->context.matched_policies &= matched_data_filter;
    return p->event->context.matched_policies != 0;
}

statfunc bool policies_matched(event_data_t *event)
{
    return event->context.matched_policies != 0;
}

statfunc bool event_is_selected(u32 event_id, u16 policies_version)
{
    void *inner_events_map = bpf_map_lookup_elem(&events_map_version, &policies_version);
    if (inner_events_map == NULL)
        return 0;

    event_config_t *event_config = bpf_map_lookup_elem(inner_events_map, &event_id);
    if (event_config == NULL)
        return 0;

    return event_config->submit_for_policies != 0;
}

statfunc u64 get_scopes_to_follow(program_data_t *p)
{
    return match_scope_filters(p);
}

#endif
