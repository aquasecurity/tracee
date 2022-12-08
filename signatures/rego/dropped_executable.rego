package tracee.TRC_9

import data.tracee.helpers

__rego_metadoc__ := {
	"id": "TRC-9",
	"version": "0.1.0",
	"name": "New Executable Was Dropped During Runtime",
	"eventName": "dropped_executable",
	"description": "An Executable file was dropped in your system during runtime. Usually container images are built with all binaries needed inside, a dropped binary may indicate an adversary infiltrated into your container.",
	"tags": ["linux", "container"],
	"properties": {
		"Severity": 2,
		"MITRE ATT&CK": "Defense Evasion: Masquerading",
	},
}

eventSelectors := [{
	"source": "tracee",
	"name": "magic_write",
	"origin": "container",
}]

tracee_selected_events[eventSelector] {
	eventSelector := eventSelectors[_]
}

tracee_match = res {
	input.eventName == "magic_write"

	file_header := helpers.get_tracee_argument("bytes")
	helpers.is_elf_file(file_header)

	pathname := helpers.get_tracee_argument("pathname")
	res := {"file path": pathname}
}
