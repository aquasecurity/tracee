package tracee.SOCKADDR

__rego_metadoc__ := {
	"id": "CEL-SOCKADDR",
	"version": "0.1.0",
	"name": "SocketAddr",
	"tags": ["linux", "container"],
}

tracee_selected_events[eventSelector] {
	eventSelector := {
		"source": "tracee",
		"name": "connect",
		"origin": "*",
	}
}

tracee_match {
	input.eventName == "connect"
	arg := input.args[_]
	arg.name == "addr"
	arg.value.sa_family == "AF_INET"
	arg.value.sin_addr == "216.58.209.14"
	arg.value.sin_port == "80"
}
