package tracee.TRC_12

import data.tracee.helpers

__rego_metadoc__ := {
	"id": "TRC-12",
	"version": "0.1.0",
	"name": "Illegitimate Shell",
	"eventName":  "illegitimate_shell",
	"description": "A program on your server spawned a shell program. Shell is the linux command-line program, server programs usually don't run shell programs, so this alert might indicate an adversary is exploiting a server program to spawn a shell on your server.",
	"tags": ["linux", "container"],
	"properties": {
		"Severity": 2,
		"MITRE ATT&CK": "Initial Access: Exploit Public-Facing Application",
	},
}

eventSelectors := [{
	"source": "tracee",
	"name": "security_bprm_check",
	"origin": "*",
}]

tracee_selected_events[eventSelector] {
	eventSelector := eventSelectors[_]
}

tracee_match {
	input.eventName == "security_bprm_check"

	pathname := helpers.get_tracee_argument("pathname")
	binary_names = ["/ash", "/bash", "/csh", "/ksh", "/sh", "/tcsh", "/zsh", "/dash"]
	binary := binary_names[_]
	endswith(pathname, binary)

	pname := input.processName
	web_server_process_names = ["nginx", "httpd", "httpd-foregroun", "lighttpd", "apache", "apache2"]
	proc_name := web_server_process_names[_]
	pname == proc_name
}
