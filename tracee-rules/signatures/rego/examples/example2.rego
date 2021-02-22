package FOO_2

__rego_metadoc__ := {
	"id": "FOO-2",
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