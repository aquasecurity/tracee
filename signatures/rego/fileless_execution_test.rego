package tracee.TRC_5

test_match_1 {
	tracee_match with input as {
		"eventName": "sched_process_exec",
		"argsNum": 1,
		"containerId": "someContainer",
		"args": [{
			"name": "pathname",
			"value": "memfd://something/something",
		}],
	}
}

test_match_2 {
	tracee_match with input as {
		"eventName": "sched_process_exec",
		"argsNum": 1,
		"containerId": "someContainer",
		"args": [{
			"name": "pathname",
			"value": "memfd:runc",
		}],
	}
}

test_match_3 {
	tracee_match with input as {
		"eventName": "sched_process_exec",
		"argsNum": 1,
		"containerId": "",
		"args": [{
			"name": "pathname",
			"value": "memfd://something/something",
		}],
	}
}

test_match_4 {
	not tracee_match with input as {
		"eventName": "sched_process_exec",
		"argsNum": 1,
		"containerId": "",
		"args": [{
			"name": "pathname",
			"value": "memfd:runc",
		}],
	}
}

test_match_5 {
	tracee_match with input as {
		"eventName": "sched_process_exec",
		"argsNum": 1,
		"containerId": "someContainer",
		"args": [{
			"name": "pathname",
			"value": "/dev/shm/something",
		}],
	}
}

test_match_6 {
	tracee_match with input as {
		"eventName": "sched_process_exec",
		"argsNum": 1,
		"containerId": "someContainer",
		"args": [{
			"name": "pathname",
			"value": "/run/shm/something",
		}],
	}
}

test_match_wrong_pathname {
	not tracee_match with input as {
		"eventName": "sched_process_exec",
		"argsNum": 1,
		"containerId": "someContainer",
		"args": [{
			"name": "pathname",
			"value": "/something/something",
		}],
	}
}
