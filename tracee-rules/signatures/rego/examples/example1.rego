package main

__rego_metadoc__ := {
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