package tracee.aio

__rego_metadoc__ := {
    "id": "TRC-3",
    "version": "0.1.0",
    "name": "Code injection",
    "description": "Possible code injection into another process",
    "tags": ["linux", "container"],
    "properties": {
        "Severity": 3,
        "MITRE ATT&CK": "Defense Evasion: Process Injection",
    }
}

eventSelectors := [
    {
        "source": "tracee",
        "name": "ptrace"
    },
    {
        "source": "tracee",
        "name": "security_file_open"
    },
    {
        "source": "tracee",
        "name": "process_vm_writev"
    }
]

tracee_selected_events[eventSelector] {
	eventSelector := eventSelectors[_]
}


tracee_match {
    input.eventName == "ptrace"
    arg_value = get_tracee_argument("request")
    arg_value == "PTRACE_POKETEXT"
}

tracee_match = res {
    input.eventName == "security_file_open"
    flags = get_tracee_argument("flags")

    is_file_write(flags)

    pathname := get_tracee_argument("pathname")

    regex.match(`/proc/(?:\d.+|self)/mem`, pathname)

    res := {
        "file flags": flags,
        "file path": pathname,
    }
}

tracee_match {
    input.eventName == "process_vm_writev"
    dst_pid = get_tracee_argument("pid")
    dst_pid != input.processId
}

get_tracee_argument(arg_name) = res {
    arg := input.args[_]
    arg.name == arg_name
    res := arg.value
}


default is_file_write(flags) = false
is_file_write(flags) {
    contains(lower(flags), "o_wronly")
}
is_file_write(flags) {
    contains(lower(flags), "o_rdwr")
}