package main

import data.tracee.helpers

__rego_metadoc__ := {
    "name": "Fileless Execution",
    "description": "Executing a precess from memory, without a file in the disk",
    "tags": ["linux", "container"],
    "properties": {
        "Severity": 2,
        "MITRE ATT&CK": "Defense Evasion: Obfuscated Files or Information",
    }
}

eventSelectors := [
    {
        "source": "tracee",
        "name": "security_bprm_check"
    }
]

tracee_selected_events[eventSelector] {
	eventSelector := eventSelectors[_]
}


tracee_match {
    input.eventName == "security_bprm_check"
    pathname = helpers.get_tracee_argument("pathname")
    startswith(pathname, "memfd:")
}
