package tracee.aio

import data.tracee.helpers

__rego_metadoc__ := {
    "id": "TRC-AIO",
    "version": "0.1.0",
    "name": "All in one Tracee signature",
    "description": "Combines Anti-Debugging and Code-injection",
    "tags": ["linux", "container"],
    "properties": {
        "Severity": 3,
        "MITRE ATT&CK": "Defense Evasion: Execution Guardrails",
    }
}

# anti_debugging
tracee_anti_debugging_tracee_selected_events[eventSelector] {
	eventSelector := {
		"source": "tracee",
		"name": "ptrace"
	}
}

tracee_anti_debugging_tracee_match {
    input.eventName == "ptrace"
    arg := input.args[_]
    arg.name == "request"
    arg.value == "PTRACE_TRACEME"
}

# code_injection
tracee_code_injection_eventSelectors := [
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

tracee_code_injection_tracee_selected_events[eventSelector] {
	eventSelector := tracee_code_injection_eventSelectors[_]
}


tracee_code_injection_tracee_match {
    input.eventName == "ptrace"
    arg_value = helpers.get_tracee_argument("request")
    arg_value == "PTRACE_POKETEXT"
}

tracee_code_injection_tracee_match = res {
    input.eventName == "security_file_open"
    flags = helpers.get_tracee_argument("flags")

    helpers.is_file_write(flags)

    pathname := helpers.get_tracee_argument("pathname")

    regex.match(`/proc/(?:\d.+|self)/mem`, pathname)

    res := {
        "file flags": flags,
        "file path": pathname,
    }
}

tracee_code_injection_tracee_match {
    input.eventName == "process_vm_writev"
    dst_pid = helpers.get_tracee_argument("pid")
    dst_pid != input.processId
}