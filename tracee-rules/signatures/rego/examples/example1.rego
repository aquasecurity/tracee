package FOO_1

__rego_metadoc__ := {
	"id": "FOO-1",
	"name": "example1"
}

tracee_selected_events[eventSelector] {
	eventSelector := {
		"source": "tracee",
		#"name": "execve"
	}
}

tracee_match {
	endswith(input.args[0].value, "yo")
}