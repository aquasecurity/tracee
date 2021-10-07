package tracee.TRC_11

import data.tracee.helpers

__rego_metadoc__ := {
    "id": "TRC-11",
    "version": "0.1.0",
    "name": "Container Host Mount Detected",
    "description": "Container root host filesystem mount detected. A mount to the host filesystem can be exploited by adversaries to perform container escape.",
    "tags": ["container"],
    "properties": {
        "Severity": 3,
        "MITRE ATT&CK": "Privilege Escalation: Escape to Host"
    }
}

eventSelectors := [
    {
        "source": "tracee",
        "name": "security_sb_mount",
        "origin": "container"
    }
]

tracee_selected_events[eventSelector] {
	eventSelector := eventSelectors[_]
}

tracee_match = res {

    input.eventName == "security_sb_mount"

    devname := helpers.get_tracee_argument("dev_name")
    regex.match(`/dev/sd\w\d+`, devname)

    res := {"mounted device": devname}
}
