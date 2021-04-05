
package tracee.TRC_RUNTIME_CONTAINER_START

import data.tracee.helpers

__rego_metadoc__ := {
    "id": "TRC-RUNTIME-CONTAINER-START",
    "version": "0.1.0",
    "name": "Identify Container Start",
    "description": "Identify a container start event",
    "tags": ["linux", "container"],
    "properties": {}
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
    input.processId == 1
    input.processName == "runc:[2:INIT]"
}