#ifndef __COMMON_FILTERING_H__
#define __COMMON_FILTERING_H__

#include <vmlinux.h>

#include <maps.h>
#include <common/logging.h>
#include <common/task.h>
#include <common/common.h>

// PROTOTYPES

statfunc void *get_event_filter_map(void *, u16, u32);
statfunc u64 binary_filter_matches(u64, void *, proc_info_t *);
statfunc u64 equality_filter_matches(u64, void *, void *);
statfunc u64 bool_filter_matches(u64, bool);
statfunc u64 match_scope_filters(program_data_t *);
statfunc u64 match_data_filters(program_data_t *, u8);
statfunc bool evaluate_scope_filters(program_data_t *);
statfunc bool evaluate_data_filters(program_data_t *, u8);
statfunc bool event_is_selected(u32);
statfunc bool rules_matched(event_data_t *);

// CONSTANTS

#define FILTER_MAX_NOT_SET 0
#define FILTER_MIN_NOT_SET ULLONG_MAX

// FUNCTIONS

// get_event_filter_map returns the filter map for the given outer map, version and event id
statfunc void *get_event_filter_map(void *outer_map, u16 version, u32 event_id)
{
    filter_version_key_t key = {
        .version = version,
        .event_id = event_id,
    };

    return bpf_map_lookup_elem(outer_map, &key);
}

statfunc u64 binary_filter_matches(u64 match_if_key_missing,
                                   void *filter_map,
                                   proc_info_t *proc_info)
{
    // check equality_filter_matches() for more info

    u64 equals_in_rules = 0;
    u64 key_used_in_rules = 0;

    if (filter_map) {
        eq_t *equality = bpf_map_lookup_elem(filter_map, proc_info->binary.path);
        if (equality == NULL) {
            // lookup by binary path and mount namespace
            equality = bpf_map_lookup_elem(filter_map, &proc_info->binary);
        }
        if (equality != NULL) {
            equals_in_rules = equality->equals_in_rules;
            key_used_in_rules = equality->key_used_in_rules;
        }
    }

    return equals_in_rules | (match_if_key_missing & ~key_used_in_rules);
}

statfunc u64 equality_filter_matches(u64 match_if_key_missing, void *filter_map, void *key)
{
    // check match_scope_filters() for initial info
    //
    //   rule 2: comm=who
    //   rule 3: comm=ping
    //   rule 4: comm!=who
    //
    // match_if_key_missing = 0000 1000, since rule 4 has "not equal" for comm filter
    // filter_map        = comm_filter
    // key               = "who" | "ping"
    //
    // ---
    //
    // considering an event from "who" command
    //
    // equals_in_rules   = 0000 0010, since rule 2 has "equal" for comm filter
    // key_used_in_rules = 0000 1010, since rule 2 and 4 are using the key "who"
    //
    // return            = equals_in_rules | (match_if_key_missing & ~key_used_in_rules)
    //                     0000 0010 |
    //                     (0000 1000 & 1111 0101) -> 0000 0000
    //
    //                     0000 0010 |
    //                     0000 0000
    //                     ---------
    //                     0000 0010 = (rule 2 matched)
    //
    // considering an event from "ping" command
    //
    // equals_in_rules   = 0000 0100, since rule 3 has "equal" for comm filter
    // key_used_in_rules = 0000 0100, since rule 3 is set for comm filter
    //
    // return            = equals_in_rules | (match_if_key_missing & ~key_used_in_rules)
    //                     0000 0100 |
    //                     (0000 1000 & 1111 1011) -> 0000 1000
    //
    //                     0000 0100 |
    //                     0000 1000
    //                     ---------
    //                     0000 1100 = (rule 3 and 4 matched)

    u64 equals_in_rules = 0;
    u64 key_used_in_rules = 0;

    if (filter_map) {
        eq_t *equality = bpf_map_lookup_elem(filter_map, key);
        if (equality != NULL) {
            equals_in_rules = equality->equals_in_rules;
            key_used_in_rules = equality->key_used_in_rules;
        }
    }

    // match if:
    // 1. key is used and equality matches (equals_in_rules)
    // 2. key is NOT used and the default action is to match
    return equals_in_rules | (match_if_key_missing & ~key_used_in_rules);
}

statfunc u64 bool_filter_matches(u64 match_bitmap, bool bool_value)
{
    // check match_scope_filters() for initial info
    //
    //   rule 5: container=true
    //
    // considering an event from a container
    //
    //   match_bitmap         = 0000 0000
    //   val                  = true
    //   return               = 0000 0000 ^
    //                          1111 1111 <- ~0ULL
    //                          ---------
    //                          1111 1111
    //
    // considering an event not from a container
    //
    //   match_bitmap         = 0000 0000
    //   val                  = false
    //   return               = 0000 0000 ^
    //                          0000 0000
    //                          ---------
    //                          0000 0000

    return match_bitmap ^ (bool_value ? ~0ULL : 0);
}

statfunc u64 match_scope_filters(program_data_t *p)
{
    task_context_t *context = &p->event->context.task;
    scope_filters_config_t *filters_cfg = &p->event->config.scope_filters;
    u32 event_id = p->event->context.eventid;
    u16 version = p->event->context.rules_version;
    void *filter_map = NULL;
    u64 res = ~0ULL;

    // Don't monitor self
    if (p->config->tracee_pid == context->host_pid)
        return 0;

    //
    // boolean filters (not using versioned filter maps)
    //

    if (filters_cfg->cont_filter_enabled) {
        bool is_container = false;
        u8 state = p->task_info->container_state;
        if (state == CONTAINER_STARTED || state == CONTAINER_EXISTED)
            is_container = true;
        u64 match_bitmap = filters_cfg->cont_filter_match_if_key_missing;
        u64 mask = ~filters_cfg->cont_filter_enabled;

        // For rules that have this filter disabled we want to set the matching bits using 'mask'
        res &= bool_filter_matches(match_bitmap, is_container) | mask;
    }

    if (filters_cfg->new_cont_filter_enabled) {
        bool is_new_container = false;
        if (p->task_info->container_state == CONTAINER_STARTED)
            is_new_container = true;
        u64 match_bitmap = filters_cfg->new_cont_filter_match_if_key_missing;
        u64 mask = ~filters_cfg->new_cont_filter_enabled;

        res &= bool_filter_matches(match_bitmap, is_new_container) | mask;
    }

    if (filters_cfg->new_pid_filter_enabled) {
        u64 match_bitmap = filters_cfg->new_pid_filter_match_if_key_missing;
        u64 mask = ~filters_cfg->new_pid_filter_enabled;

        res &= bool_filter_matches(match_bitmap, p->proc_info->new_proc) | mask;
    }

    //
    // equality filters (using versioned filter maps)
    //

    if (filters_cfg->pid_filter_enabled) {
        u64 match_if_key_missing = filters_cfg->pid_filter_match_if_key_missing;
        u64 mask = ~filters_cfg->pid_filter_enabled;

        filter_map = get_event_filter_map(&pid_filter_version, version, event_id);
        // the user might have given us a tid - check for it too
        res &= equality_filter_matches(match_if_key_missing, filter_map, &context->host_pid) |
               equality_filter_matches(match_if_key_missing, filter_map, &context->host_tid) | mask;
    }

    if (filters_cfg->uid_filter_enabled) {
        context->uid = bpf_get_current_uid_gid();
        u64 match_if_key_missing = filters_cfg->uid_filter_match_if_key_missing;
        u64 mask = ~filters_cfg->uid_filter_enabled;

        filter_map = get_event_filter_map(&uid_filter_version, version, event_id);
        res &= equality_filter_matches(match_if_key_missing, filter_map, &context->uid) | mask;
    }

    if (filters_cfg->mnt_ns_filter_enabled) {
        context->mnt_id = get_task_mnt_ns_id(p->event->task);
        u64 match_if_key_missing = filters_cfg->mnt_ns_filter_match_if_key_missing;
        u64 mask = ~filters_cfg->mnt_ns_filter_enabled;

        filter_map = get_event_filter_map(&mnt_ns_filter_version, version, event_id);
        res &= equality_filter_matches(match_if_key_missing, filter_map, &context->mnt_id) | mask;
    }

    if (filters_cfg->pid_ns_filter_enabled) {
        context->pid_id = get_task_pid_ns_id(p->event->task);
        u64 match_if_key_missing = filters_cfg->pid_ns_filter_match_if_key_missing;
        u64 mask = ~filters_cfg->pid_ns_filter_enabled;

        filter_map = get_event_filter_map(&pid_ns_filter_version, version, event_id);
        res &= equality_filter_matches(match_if_key_missing, filter_map, &context->pid_id) | mask;
    }

    if (filters_cfg->uts_ns_filter_enabled) {
        char *uts_name = get_task_uts_name(p->event->task);
        if (uts_name)
            bpf_probe_read_kernel_str(&context->uts_name, TASK_COMM_LEN, uts_name);
        u64 match_if_key_missing = filters_cfg->uts_ns_filter_match_if_key_missing;
        u64 mask = ~filters_cfg->uts_ns_filter_enabled;

        filter_map = get_event_filter_map(&uts_ns_filter_version, version, event_id);
        res &= equality_filter_matches(match_if_key_missing, filter_map, &context->uts_name) | mask;
    }

    if (filters_cfg->comm_filter_enabled) {
        bpf_get_current_comm(&context->comm, sizeof(context->comm));
        u64 match_if_key_missing = filters_cfg->comm_filter_match_if_key_missing;
        u64 mask = ~filters_cfg->comm_filter_enabled;

        filter_map = get_event_filter_map(&comm_filter_version, version, event_id);
        res &= equality_filter_matches(match_if_key_missing, filter_map, &context->comm) | mask;
    }

    if (filters_cfg->cgroup_id_filter_enabled) {
        u32 cgroup_id_lsb = context->cgroup_id;
        u64 match_if_key_missing = filters_cfg->cgroup_id_filter_match_if_key_missing;
        u64 mask = ~filters_cfg->cgroup_id_filter_enabled;

        filter_map = get_event_filter_map(&cgroup_id_filter_version, version, event_id);
        res &= equality_filter_matches(match_if_key_missing, filter_map, &cgroup_id_lsb) | mask;
    }

    if (filters_cfg->bin_path_filter_enabled) {
        u64 match_if_key_missing = filters_cfg->bin_path_filter_match_if_key_missing;
        u64 mask = ~filters_cfg->bin_path_filter_enabled;

        filter_map = get_event_filter_map(&binary_filter_version, version, event_id);
        res &= binary_filter_matches(match_if_key_missing, filter_map, p->proc_info) | mask;
    }

    return res;
}

// Function to evaluate data filters based on the program data and index.
// Returns rules bitmap.
//
// Parameters:
// - program_data_t *p: Pointer to the program data structure.
// - u8 index: Index of the string data to be used as filter.
statfunc u64 match_data_filters(program_data_t *p, u8 index)
{
    // Retrieve the string filter for the current event
    // TODO: Dynamically determine the filter and type based on policy configuration
    string_filter_config_t *str_filter = &p->event->config.data_filter.string;

    if (!(str_filter->exact_enabled || str_filter->prefix_enabled || str_filter->suffix_enabled))
        return ~0ULL;

    u64 res = 0;
    u64 explicit_disable_rules = 0;
    u64 explicit_enable_rules = 0;
    u64 default_enable_rules = 0;
    // Determine rules that do not use any type of string filter (exact, prefix, suffix)
    u64 mask_no_str_filter_rules = ~str_filter->exact_enabled & ~str_filter->prefix_enabled &
                                   ~str_filter->suffix_enabled;
    void *filter_map = NULL;

    // event ID
    u32 eventid = p->event->context.eventid;
    u16 version = p->event->context.rules_version;

    // Exact match
    if (str_filter->exact_enabled) {
        data_filter_key_t *key = get_string_data_filter_buf(DATA_FILTER_BUF1_IDX);
        if (key == NULL)
            return 0;

        __builtin_memset(key->str, 0, sizeof(key->str));

        u32 len = load_str_from_buf(&p->event->args_buf, key->str, index, FILTER_TYPE_EXACT);
        if (!len)
            return 0;

        u64 match_if_key_missing = str_filter->exact_match_if_key_missing;
        filter_map = get_event_filter_map(&data_filter_exact_version, version, eventid);
        res = equality_filter_matches(match_if_key_missing, filter_map, key);
        explicit_enable_rules |= (res & ~match_if_key_missing);
        explicit_disable_rules |= (~res & match_if_key_missing);
        default_enable_rules |= (res & match_if_key_missing);
    }

    // Prefix match
    if (str_filter->prefix_enabled) {
        data_filter_lpm_key_t *key = get_string_data_filter_lpm_buf(DATA_FILTER_BUF1_IDX);
        if (key == NULL)
            return 0;

        u32 len = load_str_from_buf(&p->event->args_buf, key->str, index, FILTER_TYPE_PREFIX);
        if (!len)
            return 0;

        // LPM tries may be created with a maximum prefix length that is a multiple of 8,
        // in the range from 8 to 2048. For more details, see:
        // https://docs.kernel.org/bpf/map_lpm_trie.html
        key->prefix_len = len * 8;

        u64 match_if_key_missing = str_filter->prefix_match_if_key_missing;
        filter_map = get_event_filter_map(&data_filter_prefix_version, version, eventid);
        res = equality_filter_matches(match_if_key_missing, filter_map, key);
        explicit_enable_rules |= (res & ~match_if_key_missing);
        explicit_disable_rules |= (~res & match_if_key_missing);
        default_enable_rules |= (res & match_if_key_missing);
    }

    // Suffix match
    if (str_filter->suffix_enabled) {
        data_filter_lpm_key_t *key = get_string_data_filter_lpm_buf(DATA_FILTER_BUF1_IDX);

        if (key == NULL)
            return 0;

        u32 len = load_str_from_buf(&p->event->args_buf, key->str, index, FILTER_TYPE_SUFFIX);
        if (!len)
            return 0;

        key->prefix_len = len * 8;

        u64 match_if_key_missing = str_filter->suffix_match_if_key_missing;
        filter_map = get_event_filter_map(&data_filter_suffix_version, version, eventid);
        res = equality_filter_matches(match_if_key_missing, filter_map, key);
        explicit_enable_rules |= (res & ~match_if_key_missing);
        explicit_disable_rules |= (~res & match_if_key_missing);
        default_enable_rules |= (res & match_if_key_missing);
    }

    // Match rules based on the following conditions:
    //
    // 1. Explicitly Enabled Rules: A rule is enabled if at least one of the three
    // filter types explicitly enables it (explicit_enable_rules).
    // 2. Default Enabled Rules: Rules that are enabled by default (default_enable_rules)
    // remain enabled only if they are not explicitly disabled (explicit_disable_rules).
    res = explicit_enable_rules | (default_enable_rules & ~explicit_disable_rules);
    // Combine rules that use string filters with those that do not
    res |= mask_no_str_filter_rules;

    return res;
}

statfunc bool evaluate_scope_filters(program_data_t *p)
{
    u64 matched_scope_filters = match_scope_filters(p);
    p->event->context.active_rules &= matched_scope_filters;
    return p->event->context.active_rules != 0 || p->event->config.has_overflow;
}

statfunc bool evaluate_data_filters(program_data_t *p, u8 index)
{
    u64 matched_data_filters = match_data_filters(p, index);
    p->event->context.active_rules &= matched_data_filters;
    return p->event->context.active_rules != 0 || p->event->config.has_overflow;
}

statfunc bool rules_matched(event_data_t *event)
{
    return event->context.active_rules != 0 || event->config.has_overflow;
}

statfunc bool event_is_selected(u32 event_id)
{
    event_config_t *event_config = bpf_map_lookup_elem(&events_config_map, &event_id);
    if (event_config == NULL)
        return 0;

    return event_config->submit_for_rules != 0;
}

statfunc u64 get_scopes_to_follow(program_data_t *p)
{
    return 0;
    // return match_scope_filters(p);
    // TODO: fixme
}

#endif
