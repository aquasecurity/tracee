package regosig_test

const (
	testRegoCodeBoolean = `package tracee.TRC_BOOL

__rego_metadoc__ := {
	"id": "TRC-BOOL",
	"version": "0.1.0",
	"name": "test name",
	"description": "test description",
	"tags": [ "tag1", "tag2" ],
	"properties": {
		"p1": "test",
		"p2": 1,
		"p3": true
	}
}

tracee_selected_events[eventSelector] {
	eventSelector := {
		"source": "tracee",
		"name": "execve"
	}
}

tracee_match {
	endswith(input.args[0].value, "yo")
}
`
	testRegoCodeObject = `package tracee.TRC_OBJECT

__rego_metadoc__ := {
	"id": "TRC-OBJECT",
	"version": "0.3.0",
	"name": "test name",
	"description": "test description",
	"tags": [ "tag1", "tag2" ],
	"properties": {
		"p1": "test",
		"p2": 1,
		"p3": true
	}
}

tracee_selected_events[eventSelector] {
	eventSelector := {
		"source": "tracee",
		"name": "ptrace"
	}
}

tracee_match = res {
	endswith(input.args[0].value, "yo")
	input.args[1].value == 1337
	res := {
		"p1": "test",
		"p2": 1,
		"p3": true
	}
}
`
	testRegoCodeInvalidObject = `package tracee.TRC_INVALID
__rego_metadoc__ := {
	"id": "TRC-INVALID",
	"version": "0.3.0",
	"name": "test name",
	"description": "test description",
	"tags": [ "tag1", "tag2" ],
	"properties": {
		"p1": "test",
		"p2": 1,
		"p3": true
	}
}

tracee_selected_events[eventSelector] {
	eventSelector := {
		"source": "tracee",
		"name": "ptrace"
	}
}

tracee_match = res {
	endswith(input.args[0].value, "invalid")
	res := "foo bar string"
}
`
)
