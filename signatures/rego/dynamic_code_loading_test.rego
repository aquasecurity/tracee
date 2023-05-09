package tracee.TRC_4

test_match_1 {
	tracee_match with input as {
		"eventName": "mem_prot_alert",
		"argsNum": 1,
		"args": [{
			"name": "alert",
			"value": "Protection changed from W to E!",
		}],
	}
}

test_match_wrong_message {
	not tracee_match with input as {
		"eventName": "mem_prot_alert",
		"argsNum": 1,
		"args": [{
			"name": "alert",
			"value": "Protection changed to Executable!",
		}],
	}
}

test_match_wrong_event {
	not tracee_match with input as {
		"eventName": "ptrace",
		"argsNum": 1,
		"args": [{
			"name": "request",
			"value": "PTRACE_PEEKDATA",
		}],
	}
}
