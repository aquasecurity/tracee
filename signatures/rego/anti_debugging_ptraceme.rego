package tracee.TRC_2

import data.tracee.helpers

__rego_metadoc__ := {
	"id": "TRC-2",
	"version": "0.1.0",
	"name": "Anti-Debugging",
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

signature_filters := [
	{
		"field": "ptrace.args.request",
		"operator": helpers.filter_equal,
		"value": ["PTRACE_TRACEME"]
	}
]

tracee_match {
	input.eventName == "ptrace"
	arg := input.args[_]
	arg.name == "request"
	arg.value == "PTRACE_TRACEME"
}
