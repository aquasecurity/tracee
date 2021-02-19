package ld_preload

import data.tracee.helpers

__rego_metadoc__ := {
    "id": "TRC-7",
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
