package tracee.TRC_3

test_match_1 {
	tracee_match with input as {
		"eventName": "ptrace",
		"argsNum": 1,
		"args": [{
			"name": "request",
			"value": "PTRACE_POKETEXT",
		}],
	}
}

test_match_2 {
	tracee_match with input as {
		"eventName": "security_file_open",
		"argsNum": 4,
		"args": [
			{
				"name": "flags",
				"value": "o_rdwr",
			},
			{
				"name": "pathname",
				"value": "/proc/543/mem",
			},
			{
				"name": "dev",
				"value": 100,
			},
			{
				"name": "inode",
				"value": 4026532486,
			},
		],
	}
}

test_match_3 {
	tracee_match with input as {
		"eventName": "process_vm_writev",
		"processId": 109,
		"argsNum": 1,
		"args": [{
			"name": "pid",
			"value": 101,
		}],
	}
}

test_match_wrong_request {
	not tracee_match with input as {
		"eventName": "ptrace",
		"argsNum": 1,
		"args": [{
			"name": "request",
			"value": "PTRACE_PEEKDATA",
		}],
	}
}

test_match_wrong_pathname {
	not tracee_match with input as {
		"eventName": "security_file_open",
		"argsNum": 4,
		"args": [
			{
				"name": "flags",
				"value": "o_rdwr",
			},
			{
				"name": "pathname",
				"value": "/var/543/mem",
			},
			{
				"name": "dev",
				"value": 100,
			},
			{
				"name": "inode",
				"value": 4026532486,
			},
		],
	}
}

test_match_pid {
	not tracee_match with input as {
		"eventName": "process_vm_writev",
		"processId": 101,
		"argsNum": 1,
		"args": [{
			"name": "pid",
			"value": 101,
		}],
	}
}
