package main

import data.tracee.helpers

__rego_metadoc__ := {
    "name": "Dynamic Code Loading",
    "description": "writing to executable allocated memory region",
    "tags": ["linux", "container"],
    "properties": {
        "Severity": 2,
        "MITRE ATT&CK": "Defense Evasion: Obfuscated Files or Information",
    }
}

eventSelectors := [
    {
        "source": "tracee",
        "name": "mem_prot_alert"
    }
]

tracee_selected_events[eventSelector] {
	eventSelector := eventSelectors[_]
}


tracee_match {
    input.eventName == "mem_prot_alert"
}
