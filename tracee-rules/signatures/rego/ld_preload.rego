package tracee.TRC_7

import data.tracee.helpers

__rego_metadoc__ := {
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

eventSelectors := [
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
	eventSelector := eventSelectors[_]
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
