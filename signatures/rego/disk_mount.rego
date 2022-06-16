package tracee.TRC_11

import data.tracee.helpers

__rego_metadoc__ := {
	"id": "TRC-11",
	"version": "0.1.0",
	"name": "Container Device Mount Detected",
	"description": "Container device filesystem mount detected. A mount of a host device filesystem can be exploited by adversaries to perform container escape.",
	"tags": ["container"],
	"properties": {
		"Severity": 3,
		"MITRE ATT&CK": "Privilege Escalation: Escape to Host",
	},
}

eventSelectors := [{
	"source": "tracee",
	"name": "security_sb_mount",
	"origin": "container",
}]

tracee_selected_events[eventSelector] {
	eventSelector := eventSelectors[_]
}

signature_filters := [
	{
		"field": "security_sb_mount.args.dev_name",
		"operator": helpers.filter_equal,
		"value": ["/dev/*"]
	},
	{
		"field": "security_sb_mount.context.processName",
		"operator": helpers.filter_notequal,
		"value": ["runc:*"]
	},
	{
		"field": "security_sb_mount.context.threadId",
		"operator": helpers.filter_notequal,
		"value": [1]
	}
]

tracee_match = res {
	input.eventName == "security_sb_mount"

	devname := helpers.get_tracee_argument("dev_name")
	startswith(devname, "/dev/")

	# exclude runc
	not runc_process with input as input

	res := {"mounted device": devname}
}

runc_process {
	startswith(input.processName, "runc:")
	input.threadId == 1
}
