package tracee.TRC_5

import data.tracee.helpers

__rego_metadoc__ := {
	"id": "TRC-5",
	"version": "0.1.0",
	"name": "Fileless Execution",
	"description": "Executing a process from memory, without a file in the disk",
	"tags": ["linux", "container"],
	"properties": {
		"Severity": 2,
		"MITRE ATT&CK": "Defense Evasion: Obfuscated Files or Information",
	},
}

eventSelectors := [{
	"source": "tracee",
	"name": "sched_process_exec",
}]

tracee_selected_events[eventSelector] {
	eventSelector := eventSelectors[_]
}

tracee_match {
	input.eventName == "sched_process_exec"
	pathname = helpers.get_tracee_argument("pathname")
	startswith(pathname, "memfd:")

	not startswith(pathname, "memfd:runc")
	input.containerId == ""
}

tracee_match {
	input.eventName == "sched_process_exec"
	pathname = helpers.get_tracee_argument("pathname")
	startswith(pathname, "memfd:")

	input.containerId != ""
}

tracee_match {
	input.eventName == "sched_process_exec"
	pathname = helpers.get_tracee_argument("pathname")
	startswith(pathname, "/dev/shm")
}

tracee_match {
	input.eventName == "sched_process_exec"
	pathname = helpers.get_tracee_argument("pathname")
	startswith(pathname, "/run/shm")
}
