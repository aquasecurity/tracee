package tracee.TRC_6

import data.tracee.helpers

__rego_metadoc__ := {
	"id": "TRC-6",
	"version": "0.1.0",
	"name": "kernel module loading",
	"eventName": "kernel_module_loading",
	"description": "Attempt to load a kernel module detection",
	"tags": ["linux", "container"],
	"properties": {
		"Severity": 3,
		"MITRE ATT&CK": "Persistence: Kernel Modules and Extensions",
	},
}

eventSelectors := [
	{
		"source": "tracee",
		"name": "init_module",
	},
	{
		"source": "tracee",
		"name": "security_kernel_read_file",
	},
]

tracee_selected_events[eventSelector] {
	eventSelector := eventSelectors[_]
}

tracee_match {
	input.eventName == "init_module"
}

tracee_match = res {
	input.eventName == "security_kernel_read_file"

	load_type = helpers.get_tracee_argument("type")

	load_type == "kernel-module"

	res := {"pathname": helpers.get_tracee_argument("pathname")}
}
