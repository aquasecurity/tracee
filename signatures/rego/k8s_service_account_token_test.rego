package tracee.TRC_8

test_match_1 {
	tracee_match with input as {
		"processId": 1000,
		"hostProcessId": 1,
		"eventName": "security_file_open",
		"processName": "test",
		"args": [
			{
				"name": "flags",
				"value": "O_RDONLY",
			},
			{
				"name": "pathname",
				"value": "/var/run/secrets/kubernetes.io/serviceaccount/token",
			},
		],
	}
}

test_match_wrong_request {
	not tracee_match with input as {
		"eventName": "security_file_open",
		"processId": 1,
		"hostProcessId": 1,
		"args": [
			{
				"name": "flags",
				"value": "O_RDONLY",
			},
			{
				"name": "pathname",
				"value": "/var/run/secrets/docker/service/token",
			},
		],
	}
}

test_match_wrong_process_name {
	not tracee_match with input as {
		"processId": 1000,
		"hostProcessId": 1,
		"eventName": "security_file_open",
		"processName": "kubectl",
		"args": [
			{
				"name": "flags",
				"value": "O_RDONLY",
			},
			{
				"name": "pathname",
				"value": "/var/run/secrets/kubernetes.io/serviceaccount/token",
			},
		],
	}
}
