package tracee.TRC_15

test_match_diamorphine_rootkit_output {
    tracee_match with input as {
        "eventName": "detect_hooked_syscalls",
        "argsNum": 1,
        "args": [
            {
                "name": "hooked_syscalls",
                "value": [{"SyscallName":"kill","ModuleOwner":"diamorphine"},{"SyscallName":"getdents","ModuleOwner":"diamorphine"},{"SyscallName":"getdents64","ModuleOwner":"diamorphine"}]
            }
        ]
    }
}

test_match_custom_output {
    tracee_match with input as {
        "eventName": "detect_hooked_syscalls",
        "argsNum": 1,
        "args": [
            {
                "name": "hooked_syscalls",
                "value": [{"SyscallName":"open","ModuleOwner":"diamorphine"},{"SyscallName":"read","ModuleOwner":"diamorphine"}]
            }
        ]
    }
}

test_match_empty_array {
    not tracee_match with input as {
        "eventName": "detect_hooked_syscalls",
        "argsNum": 1,
        "args": [
            {
                "name": "hooked_syscalls",
                "value": []
            }
        ]
    }
}
