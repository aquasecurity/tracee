package tracee.TRC_14

import data.tracee.helpers

__rego_metadoc__ := {
	"id": "TRC-14",
	"version": "0.1.0",
	"name": "CGroups Release Agent File Modification",
	"eventName": "cgroup_release_agent",
	"description": "An Attempt to modify CGroups release agent file was detected. CGroups are a Linux kernel feature which can change a process's resource limitations. Adversaries may use this feature for container escaping.",
	"properties": {
		"Severity": 3,
		"MITRE ATT&CK": "Privilege Escalation: Escape to Host",
	},
}

eventSelectors := [{
	"source": "tracee",
	"name": "security_file_open",
	"origin": "container",
}]

tracee_selected_events[eventSelector] {
	eventSelector := eventSelectors[_]
}

tracee_match = res {
	input.eventName == "security_file_open"
	flags = helpers.get_tracee_argument("flags")

	helpers.is_file_write(flags)

	pathname := helpers.get_tracee_argument("pathname")

	endswith(pathname, "/release_agent")

	res := {
		"File Flags": flags,
		"File Path": pathname,
	}
}
