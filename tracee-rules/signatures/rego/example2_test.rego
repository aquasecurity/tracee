package main

test_match_1 {
    tracee_match == { "Severity": 1 } with input as {
        "eventName": "whatever", 
        "argsNum": 1, 
        "args": [
            {
                "name": "whatever", 
                "value": "ends with yo" 
            }
        ]
    }
}

test_match_wrong_arg_value {
    not tracee_match with input as {
        "eventName": "whatever", 
        "argsNum": 1, 
        "args": [
            {
                "name": "whatever", 
                "value": "doesn't ends with yo!" 
            }
        ]
    }
}
