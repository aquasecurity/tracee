package tracee.TRC_16

import data.tracee.helpers

__rego_metadoc__ := {
	"id": "TRC-16",
	"version": "0.1.0",
	"name": "Hooking proc file system file operations by overriding the function pointers",
	"eventName": "proc_fops_hooking",
	"description": "Usage of kernel modules to hook file operations",
	"tags": ["linux"],
	"properties": {
		"Severity": 4,
		"MITRE ATT&CK": "Defense Evasion: Rootkit",
	},
}

eventSelectors := [{
	"source": "tracee",
	"name": "hooked_proc_fops",
}]

tracee_selected_events[eventSelector] {
	eventSelector := eventSelectors[_]
}

tracee_match = res {
	input.eventName == "hooked_proc_fops"
	hooked_proc_fops_arr := helpers.get_tracee_argument("hooked_fops_pointers")
	c := count(hooked_proc_fops_arr)
	c > 0
	res := {"hooked file_operations": hooked_proc_fops_arr}
}
