package tracee.aio
 import data.tracee.helpers


__rego_metadoc__tracee.TRC_2 := {
    "id": "TRC-2",
    "version": "0.1.0",
    "name": "Anti-Debugging",
    "description": "Process uses anti-debugging technique to block debugger",
    "tags": ["linux", "container"],
    "properties": {
        "Severity": 3,
        "MITRE ATT&CK": "Defense Evasion: Execution Guardrails",
    }
}

tracee_selected_events[eventSelector] {
        eventSelector := {
                "source": "tracee",
                "name": "ptrace"
        }
}

tracee_match {
    input.eventName == "ptrace"
    arg := input.args[_]
    arg.name == "request"
    arg.value == "PTRACE_TRACEME"
}




__rego_metadoc__tracee.TRC_3 := {
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

eventSelectors_1 := [
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
        eventSelector := eventSelectors_1[_]
}


tracee_match {
    input.eventName == "ptrace"
    arg_value = helpers.get_tracee_argument("request")
    arg_value == "PTRACE_POKETEXT"
}

tracee_match = res {
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

tracee_match {
    input.eventName == "process_vm_writev"
    dst_pid = helpers.get_tracee_argument("pid")
    dst_pid != input.processId
}




__rego_metadoc__tracee.TRC_4 := {
    "id": "TRC-4",
    "version": "0.1.0",
    "name": "Dynamic Code Loading",
    "description": "Writing to executable allocated memory region",
    "tags": ["linux", "container"],
    "properties": {
        "Severity": 2,
        "MITRE ATT&CK": "Defense Evasion: Obfuscated Files or Information",
    }
}

eventSelectors_2 := [
    {
        "source": "tracee",
        "name": "mem_prot_alert"
    }
]

tracee_selected_events[eventSelector] {
        eventSelector := eventSelectors_2[_]
}


tracee_match {
    input.eventName == "mem_prot_alert"
    message := helpers.get_tracee_argument("alert")
    message == "Protection changed from W+E to E!"
}




__rego_metadoc__tracee.TRC_5 := {
    "id": "TRC-5",
    "version": "0.1.0",
    "name": "Fileless Execution",
    "description": "Executing a process from memory, without a file in the disk",
    "tags": ["linux", "container"],
    "properties": {
        "Severity": 2,
        "MITRE ATT&CK": "Defense Evasion: Obfuscated Files or Information",
    }
}

eventSelectors_3 := [
    {
        "source": "tracee",
        "name": "security_bprm_check"
    }
]

tracee_selected_events[eventSelector] {
        eventSelector := eventSelectors_3[_]
}


tracee_match {
    input.eventName == "security_bprm_check"
    pathname = helpers.get_tracee_argument("pathname")
    startswith(pathname, "memfd:")
}

tracee_match {
    input.eventName == "security_bprm_check"
    pathname = helpers.get_tracee_argument("pathname")
    startswith(pathname, "/dev/shm")
}


__rego_metadoc__tracee.TRC_6 := {
    "id": "TRC-6",
    "version": "0.1.0",
    "name": "kernel module loading",
    "description": "Attempt to load a kernel module detection",
    "tags": ["linux", "container"],
    "properties": {
        "Severity": 3,
        "MITRE ATT&CK": "Persistence: Kernel Modules and Extensions",
    }
}

eventSelectors_4 := [
    {
        "source": "tracee",
        "name": "init_module"
    },
    {
        "source": "tracee",
        "name": "finit_module"
    }
]

tracee_selected_events[eventSelector] {
        eventSelector := eventSelectors_4[_]
}


tracee_match {
    input.eventName == "init_module"
}

tracee_match {
    input.eventName == "finit_module"
}




__rego_metadoc__tracee.TRC_7 := {
    "id": "TRC-7",
    "version": "0.1.0",
    "name": "LD_PRELOAD",
    "description": "Usage of LD_PRELOAD to allow hooks on process",
    "tags": ["linux", "container"],
    "properties": {
        "Severity": 2,
        "MITRE ATT&CK": "Persistence: Hijack Execution Flow",
    }
}

eventSelectors_5 := [
    {
        "source": "tracee",
        "name": "execve"
    },
    {
     "source": "tracee",
     "name": "security_file_open"
    }
]

tracee_selected_events[eventSelector] {
        eventSelector := eventSelectors_5[_]
}


tracee_match {
    input.eventName == "execve"
    envp = helpers.get_tracee_argument("envp")

    envvar := envp[_]
    startswith(envvar, "LD_PRELOAD")
}

tracee_match {
    input.eventName == "execve"
    envp = helpers.get_tracee_argument("envp")

    envvar := envp[_]
    startswith(envvar, "LD_LIBRARY_PATH")
}

tracee_match {
    input.eventName == "security_file_open"
    flags = helpers.get_tracee_argument("flags")

    helpers.is_file_write(flags)

    pathname := helpers.get_tracee_argument("pathname")

    pathname == "/etc/ld.so.preload"
}
]
