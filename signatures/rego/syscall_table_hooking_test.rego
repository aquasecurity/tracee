package tracee.TRC_15

test_match_diamorphine_rootkit_output {
	tracee_match with input as {
		"eventName": "hooked_syscalls",
		"argsNum": 1,
		"args": [{
			"name": "hooked_syscalls",
			"value": [{"SymbolName": "kill", "ModuleOwner": "diamorphine"}, {"SymbolName": "getdents", "ModuleOwner": "diamorphine"}, {"SymbolName": "getdents64", "ModuleOwner": "diamorphine"}],
		}],
	}
}

test_match_custom_output {
	tracee_match with input as {
		"eventName": "hooked_syscalls",
		"argsNum": 1,
		"args": [{
			"name": "hooked_syscalls",
			"value": [{"SymbolName": "open", "ModuleOwner": "diamorphine"}, {"SymbolName": "read", "ModuleOwner": "diamorphine"}],
		}],
	}
}

test_match_empty_array {
	not tracee_match with input as {
		"eventName": "hooked_syscalls",
		"argsNum": 1,
		"args": [{
			"name": "hooked_syscalls",
			"value": [],
		}],
	}
}
