package tracee.TRC_16

test_match_rootkit_output {
	tracee_match with input as {
		"eventName": "hooked_proc_fops",
		"argsNum": 1,
		"args": [{
			"name": "hooked_fops_pointers",
			"value": [{"SymbolName": "struct file_operations pointer", "ModuleOwner": "phide"}, {"SymbolName": "iterate_shared", "ModuleOwner": "phide"}, {"SymbolName": "iterate", "ModuleOwner": "phide"}],
		}],
	}
}

test_match_empty_array {
	not tracee_match with input as {
		"eventName": "hooked_proc_fops",
		"argsNum": 1,
		"args": [{
			"name": "hooked_fops_pointers",
			"value": [],
		}],
	}
}
