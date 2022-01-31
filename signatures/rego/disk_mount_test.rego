package tracee.TRC_11

test_match_1 {
    tracee_match with input as {
        "eventName": "security_sb_mount", 
        "argsNum": 1, 
        "args": [
            {
                "name": "dev_name",
                "type": "const char*",
                "value": "/dev/sda3"
            }
        ]
    }
}

test_match_2 {
    tracee_match with input as {
        "eventName": "security_sb_mount",
        "argsNum": 1,
        "args": [
            {
                "name": "dev_name",
                "type": "const char*",
                "value": "/dev/vda1"
            }
        ]
    }
}

test_match_wrong_request {
    not tracee_match with input as {
        "eventName": "security_sb_mount", 
        "argsNum": 1, 
        "args": [
        {
            "name": "dev_name",
            "type": "const char*",
            "value": "/disk"
        }
    ]
    }
}

