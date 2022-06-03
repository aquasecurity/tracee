package tracee.TRC_6

test_match_1 {
	tracee_match with input as {
		"eventName": "init_module",
		"argsNum": 0,
	}
}

test_match_2 {
	tracee_match with input as {
		"eventName": "security_kernel_read_file",
		"argsNum": 4,
		"args": [
			{
				"name": "pathname",
				"value": "/path/to/kernel/module.ko",
			},
			{
				"name": "dev",
				"value": 100,
			},
			{
				"name": "inode",
				"value": 4026532486,
			},
			{
				"name": "type",
				"value": "kernel-module",
			},
		],
	}
}

test_match_deprecated_event {
	not tracee_match with input as {
		"eventName": "finit_module",
		"argsNum": 0,
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

test_match_wrong_type {
	not tracee_match with input as {
		"eventName": "security_kernel_read_file",
		"argsNum": 4,
		"args": [
			{
				"name": "pathname",
				"value": "/path/to/kernel/module.ko",
			},
			{
				"name": "dev",
				"value": 100,
			},
			{
				"name": "inode",
				"value": 4026532486,
			},
			{
				"name": "type",
				"value": "security-policy",
			},
		],
	}
}
