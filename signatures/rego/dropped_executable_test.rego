package tracee.TRC_9

test_match_1 {
	tracee_match == {"file path": "new_file"} with input as {
		"eventName": "magic_write",
		"args": [
			{
				"name": "bytes",
				"value": "f0VMRgIBAQAAAAAAAAAAAA==",
			},
			{
				"name": "pathname",
				"value": "new_file",
			},
		],
	}
}

test_match_wrong_request {
	not tracee_match with input as {
		"eventName": "magic_write",
		"args": [{
			"name": "bytes",
			"value": "fMMVMRgIBAQAAAAAAAAAAAA==",
		}],
	}
}
