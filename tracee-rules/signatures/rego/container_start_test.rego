package tracee.TRC_13

test_match_1 {
    tracee_match with input as {
        "eventName": "execve",
        "processId": 1,
        "processName": "runc:[2:INIT]"
    }
}

test_match_wrong_request {
    not tracee_match with input as {
    "eventName": "execve",
    "processId": 5,
    "processName": "runc:[2:INIT]"
  }
}
