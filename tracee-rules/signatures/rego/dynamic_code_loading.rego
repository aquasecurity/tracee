package tracee.TRC_4

import data.tracee.helpers

__rego_metadoc__ := {
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
    message := helpers.get_tracee_argument("alert")
    message == "Protection changed from W+E to E!"
}
