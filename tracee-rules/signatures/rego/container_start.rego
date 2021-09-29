package tracee.TRC_13

import data.tracee.helpers

__rego_metadoc__ := {
    "id": "TRC-13",
    "version": "0.1.0",
    "name": "Container Deployed",
    "description": "A New container was deployed on your host. Adversaries may deploy containers on your host to avoid detection and as a hidden backdoor to your host.",
    "tags": ["container"],
    "properties": {
        "Severity": 0,
        "MITRE ATT&CK": "Defense Evasion: Deploy Container"
    }
}

eventSelectors := [
    {
       "source": "tracee",
       "name": "execve",
       "origin": "container"
    }
]

tracee_selected_events[eventSelector] {
	eventSelector := eventSelectors[_]
}

tracee_match {
    input.eventName == "execve"
    input.processId == 1
    input.processName == "runc:[2:INIT]"
}
