#ifndef __STACK_UNWIND_H__
#define __STACK_UNWIND_H__

#include "maps.h"

statfunc bool stack_trace_enabled_for_event(u32 event_id)
{
    return bpf_map_lookup_elem(&su_enabled_evts, &event_id) != NULL;
}

#endif /* __STACK_UNWIND_H__ */