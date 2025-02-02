#ifndef __STACK_UNWIND_MAPS_H__
#define __STACK_UNWIND_MAPS_H__

#include <maps.h>

struct stack_unwind_enabled_events {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, MAX_EVENT_ID);
    __type(key, u32);
    __type(value, u32);
} su_enabled_evts SEC(".maps");

#endif /* __STACK_UNWIND_MAPS_H__ */