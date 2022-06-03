package tracee.TRC_14

test_match_1 {
	tracee_match with input as {
		"eventName": "security_file_open",
		"argsNum": 2,
		"args": [
			{
				"name": "pathname",
				"type": "const char*",
				"value": "/tmp/cgrp/release_agent",
			},
			{
				"name": "flags",
				"type": "int",
				"value": "O_WRONLY|O_CREAT|O_TRUNC|O_LARGEFILE",
			},
		],
	}
}

test_match_wrong_request {
	not tracee_match with input as {
		"eventName": "security_file_open",
		"argsNum": 2,
		"args": [
			{
				"name": "pathname",
				"type": "const char*",
				"value": "/tmp/cgrp/release_agent",
			},
			{
				"name": "flags",
				"type": "int",
				"value": "O_RDONLY",
			},
		],
	}
}
