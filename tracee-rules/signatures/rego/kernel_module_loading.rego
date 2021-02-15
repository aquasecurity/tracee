package main

__rego_metadoc__ := {
    "name": "kernel module loading",
    "description": "Attempt to load a kernel module detection",
    "tags": ["linux", "container"],
    "properties": {
        "Severity": 3,
        "MITRE ATT&CK": "Persistence: Kernel Modules and Extensions",
    }
}

eventSelectors := [
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
	eventSelector := eventSelectors[_]
}


tracee_match {
    input.eventName == "init_module"
}

tracee_match {
    input.eventName == "finit_module"
}
