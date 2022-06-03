package tracee.TRC_12

test_match_1 {
	tracee_match with input as {
		"eventName": "security_bprm_check",
		"processName": "apache2",
		"args": [{
			"name": "pathname",
			"value": "/bin/dash",
		}],
	}
}

test_match_wrong_request {
	not tracee_match with input as {
		"processName": "apache2",
		"eventName": "security_bprm_check",
		"args": [{
			"name": "pathname",
			"value": "/johnny_boy",
		}],
	}
}
