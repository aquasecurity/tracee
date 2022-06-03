package tracee.TRC_7

test_match_1 {
	tracee_match with input as {
		"eventName": "execve",
		"argsNum": 2,
		"args": [
			{
				"name": "envp",
				"value": ["FOO=BAR", "LD_PRELOAD=/something"],
			},
			{
				"name": "argv",
				"value": ["ls"],
			},
		],
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
				"value": "/etc/ld.so.preload",
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

test_match_no_ld_preload {
	not tracee_match with input as {
		"eventName": "execve",
		"argsNum": 2,
		"args": [
			{
				"name": "envp",
				"value": ["FOO=BAR"],
			},
			{
				"name": "argv",
				"value": ["ls"],
			},
		],
	}
}

test_match_wrong_path {
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
				"value": "/etc/ld.preload",
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
