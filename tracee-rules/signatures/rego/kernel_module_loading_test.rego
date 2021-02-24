package tracee.TRC_6

test_match_1 {
    tracee_match with input as {
        "eventName": "init_module",
        "argsNum": 0
    }
}

test_match_2 {
    tracee_match with input as {
        "eventName": "finit_module",
        "argsNum": 0
    }
}

test_match_wrong_event {
    not tracee_match with input as {
        "eventName": "ptrace", 
        "argsNum": 1, 
        "args": [
            {
                "name": "request", 
                "value": "PTRACE_PEEKDATA"
            }
        ]
    }
}

