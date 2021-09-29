package tracee.TRC_14

import data.tracee.helpers

__rego_metadoc__ := {
    "id": "TRC-14",
    "version": "0.1.0",
    "name": "Container Stopped",
    "description": "A container running on the host was stopped.",
    "tags": ["container"],
    "properties": {
        "Severity": 0,
        "MITRE ATT&CK": "Defense Evasion: Deploy Container"
    }
}

eventSelectors := [
    {
       "source": "tracee",
       "name": "sched_process_exit",
       "origin": "container"
    }
]

tracee_selected_events[eventSelector] {
	eventSelector := eventSelectors[_]
}

tracee_match {
    input.eventName == "sched_process_exit"
    input.processId == 1
}
