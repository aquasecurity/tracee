package main

test_match_1 {
    tracee_match with input as {
        "eventName": "ptrace", 
        "argsNum": 1, 
        "args": [
            {
                "name": "request", 
                "value": "PTRACE_POKETEXT"
            }
        ]
    }
}

test_match_2 {
    tracee_match with input as {
        "eventName": "open",
        "argsNum": 2,
        "args": [
            {
                "name": "flags",
                "value": "o_rdwr"
            },
            {
                "name": "pathname",
                "value": "/proc/543/mem"
            }
        ]
    }
}

test_match_3 {
    tracee_match with input as {
        "eventName": "openat",
        "argsNum": 2,
        "args": [
            {
                "name": "flags",
                "value": "o_rdwr"
            },
            {
                "name": "pathname",
                "value": "/proc/543/mem"
            }
        ]
    }
}

test_match_wrong_request {
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

test_match_wrong_pathname {
    tracee_match with input as {
        "eventName": "openat",
        "argsNum": 2,
        "args": [
            {
                "name": "flags",
                "value": "o_rdwr"
            },
            {
                "name": "pathname",
                "value": "/var/543/mem"
            }
        ]
    }
}
