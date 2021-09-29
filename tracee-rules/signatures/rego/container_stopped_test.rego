package tracee.TRC_14

test_match_1 {
    tracee_match with input as {
        "eventName": "sched_process_exit",
        "processId": 1,
    }
}

test_match_wrong_request {
    not tracee_match with input as {
    "eventName": "sched_process_exit",
    "processId": 5,
  }
}
