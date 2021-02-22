package tracee.TRC_7

test_match_1 {
    tracee_match with input as {
        "eventName": "execve",
        "argsNum": 2,
        "args": [
            {
                "name": "envp",
                "value": ["FOO=BAR", "LD_PRELOAD=/something"]
            },
            {
                "name": "argv",
                "value": ["ls"]
            }
        ]
    }
}

test_match_no_ld_preload {
    not tracee_match with input as {
        "eventName": "execve",
        "argsNum": 2,
        "args": [
            {
                "name": "envp",
                "value": ["FOO=BAR"]
            },
            {
                "name": "argv",
                "value": ["ls"]
            }
        ]
    }
}

