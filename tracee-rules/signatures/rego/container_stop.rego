
package tracee.TRC_RUNTIME_CONTAINER_STOP

import data.tracee.helpers

__rego_metadoc__ := {
    "id": "TRC-RUNTIME-CONTAINER-STOP",
    "version": "0.1.0",
    "name": "Identify Container Stop",
    "description": "Identify a container stop event",
    "tags": ["linux", "container"],
    "properties": {}
}

eventSelectors := [
    {
        "source": "tracee",
        "name": "sched_process_exit"
    }
]

tracee_selected_events[eventSelector] {
	eventSelector := eventSelectors[_]
}

tracee_match {
    input.eventName == "sched_process_exit"
    input.processId == 1
    input.processName != "runc:[2:INIT]"
}