package tracee.TRC_2

import data.tracee.helpers

__rego_metadoc__ := {
	"id": "TRC-2",
	"version": "0.1.0",
	"name": "Anti-Debugging",
	"eventName": "anti_debugging",
	"description": "Process uses anti-debugging technique to block debugger",
	"tags": ["linux", "container"],
	"properties": {
		"Severity": 3,
		"MITRE ATT&CK": "Defense Evasion: Execution Guardrails",
	},
}

tracee_selected_events[eventSelector] {
	eventSelector := {
		"source": "tracee",
		"name": "ptrace",
	}
}

tracee_match {
	input.eventName == "ptrace"
	request := helpers.get_tracee_argument("request")
	request == "PTRACE_TRACEME"
}
