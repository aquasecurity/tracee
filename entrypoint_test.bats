#!/usr/bin/env bats

load test/bats-helpers.bash

setup() {
    export PATH="$PWD/test/mocks:$PATH"
    log=$(mktemp)
    export MOCK_LOG=$log
    export TRACEE_EBPF_EXE="tracee-ebpf"
    export TRACEE_RULES_EXE="tracee-rules"
    export TRACEE_WEBHOOK_EXE="falco-sidekick"
    export TRACEE_WEBHOOK_CONFIG="$0" #some existing file
    export TRACEE_MOUNT_EXE="mount"
}

teardown() {
    rm $log
}

@test "mount debugfs" {
    run ./entrypoint.sh
    assert_success
    assert_contains 'mounted'
}

@test "don't mount debugfs" {
    export MOCK_MOUNT_EXISTS=true
    run ./entrypoint.sh
    assert_success
    assert_absent 'mounted'
}

@test "trace" {
    run ./entrypoint.sh trace --output json -t event=execve --capture dir:/something
    assert_success
    assert_contains 'tracee-ebpf --output json -t event=execve --capture dir:/something' $log
}

@test "config integrations" {
    run ./entrypoint.sh
    assert_success
    assert_contains "$TRACEE_WEBHOOK_EXE --config-file=$0"
}

@test "select rules" {
    run ./entrypoint.sh --rules 'example1,example2'
    assert_success
    assert_contains "$TRACEE_RULES_EXE .* --rules=example1,example2" $log
}

@test "no flags" {
    run ./entrypoint.sh
    assert_success
    assert_contains "$TRACEE_WEBHOOK_EXE --config-file=$0"
    assert_contains "processed: event1"
    assert_contains "$TRACEE_RULES_EXE --input-tracee=file:stdin --input-tracee=format:gob --webhook=http://localhost:2801" $log
    assert_contains "$TRACEE_EBPF_EXE --output=format:gob --security-alerts" $log
}
