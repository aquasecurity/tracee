package main

test_match_1 {
    tracee_match with input as {
        "eventName": "security_bprm_check",
        "argsNum": 1,
        "args": [
            {
                "name": "pathname",
                "value": "memfd://something/something"
            }
        ]
    }
}

test_match_wrong_pathname {
    not tracee_match with input as {
        "eventName": "security_bprm_check",
        "argsNum": 1,
        "args": [
            {
                "name": "pathname",
                "value": "/something/something"
            }
        ]
    }
}

