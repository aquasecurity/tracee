package main

__rego_metadoc__ := {
    "id": "TRC-12345",
	"name": "example2"
}

tracee_selected_events[eventSelector] {
	eventSelector := {
		"source": "tracee",
		#"name": "execve"
	}
}

tracee_match = res {
	endswith(input.args[0].value, "yo")
	res := { "Severity": 1 }
}