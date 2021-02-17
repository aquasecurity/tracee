package main

test_match_1 {
    tracee_match with input as {
        "eventName": "mem_prot_alert",
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

