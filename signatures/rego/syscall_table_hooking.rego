package tracee.TRC_15

import data.tracee.helpers

__rego_metadoc__ := {
    "id": "TRC-15",
    "version": "0.1.0",
    "name": "Hooking system calls by override the system call table entires",
    "description": "Usage of kernel module to hooks system calls",
    "tags": ["linux"],
    "properties": {
        "Severity": 5,
        "MITRE ATT&CK": "Persistence: Hooking system calls entires in the system-call table",
    }
}

eventSelectors := [
    {
        "source": "tracee",
        "name": "detect_hooked_syscalls"
    },
]

tracee_selected_events[eventSelector] {
	eventSelector := eventSelectors[_]
}

tracee_match = res {
    input.eventName == "detect_hooked_syscalls"
    hooked_syscalls_arr := helpers.get_tracee_argument("hooked_syscalls")
    c := count(hooked_syscalls_arr)
    c > 0
    res :={"hooked syscall": hooked_syscalls_arr}

}