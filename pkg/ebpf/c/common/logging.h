#ifndef __COMMON_LOGGING_H__
#define __COMMON_LOGGING_H__

#include <vmlinux.h>

#include <common/common.h>

statfunc void do_tracee_log(
    void *ctx, enum bpf_log_level level, enum bpf_log_id id, s64 ret, u32 line, void *file)
{
    if (!ctx || !file)
        return;

    u32 zero = 0;
    bpf_log_output_t *log_output = bpf_map_lookup_elem(&scratch_map, &zero);
    if (unlikely(log_output == NULL))
        return;

    log_output->level = level;
    log_output->id = id;

    log_output->log.ret = ret;
    log_output->log.cpu = bpf_get_smp_processor_id();
    log_output->log.line = line;

    u64 fsize = __builtin_strlen(file);
    if (unlikely(fsize >= BPF_MAX_LOG_FILE_LEN))
        fsize = BPF_MAX_LOG_FILE_LEN - 1;
    __builtin_memcpy(log_output->log.file, file, fsize);
    log_output->log.file[fsize] = '\0';

    bpf_log_count_t counter_buf = {};
    counter_buf.count = 1;
    counter_buf.ts = bpf_ktime_get_ns(); // store the current ts
    u64 ts_prev = 0;

    bpf_log_count_t *counter = bpf_map_lookup_elem(&logs_count, &log_output->log);
    if (likely(counter != NULL)) {
        ts_prev = counter->ts; // store previous ts

        counter->count += 1;
        counter->ts = counter_buf.ts; // set to current ts
    } else {
        counter = &counter_buf;
        bpf_map_update_elem(&logs_count, &log_output->log, counter, BPF_ANY);
    }

    // submit log when its cpu occurrence time diff is greater than 2s
    if ((counter->ts - ts_prev) > (u64) 2000000000) {
        log_output->count = counter->count;
        bpf_perf_event_output(ctx, &logs, BPF_F_CURRENT_CPU, log_output, sizeof(*log_output));
        counter->count = 0; // reset, assuming that the consumer is incrementing
    }
}

#define tracee_log(ctx, level, id, ret) do_tracee_log(ctx, level, id, ret, __LINE__, __FILE__);

#endif
