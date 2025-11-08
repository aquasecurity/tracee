#!/bin/sh
# Unit tests for lib.sh

__LIB_DIR="${0%/*}"
# shellcheck disable=SC1091
. "${__LIB_DIR}/lib.sh"

test___collect_missing_cmds() {
    # case 1: test with all commands available
    result=$(__collect_missing_cmds echo grep sed)
    test_assert_eq "" "${result}" "__collect_missing_cmds returns empty when all commands exist"

    # case 2: test with one command missing
    result=$(__collect_missing_cmds echo nonexistentcmd)
    test_assert_eq " nonexistentcmd" "${result}" "__collect_missing_cmds detects one missing command"

    # case 3: test with multiple commands missing
    result=$(__collect_missing_cmds echo nonexistent1 printf nonexistent2)

    found_one=$(printf "%s" "${result}" | grep -c "nonexistent1")
    test_assert_eq 1 "${found_one}" "__collect_missing_cmds finds nonexistent1"
    found_two=$(printf "%s" "${result}" | grep -c "nonexistent2")
    test_assert_eq 1 "${found_two}" "__collect_missing_cmds finds nonexistent2"
}

test___lib_require_cmds() {
    # case 1: test with all commands available (using POSIX-guaranteed commands)
    __lib_require_cmds cat test true > /dev/null 2>&1
    test_assert_eq 0 "$?" "__lib_require_cmds returns exit code 0 when all commands exist"

    # case 2: test with only guaranteed-to-exist commands
    __lib_require_cmds sh cat printf > /dev/null 2>&1
    test_assert_eq 0 "$?" "__lib_require_cmds returns exit code 0 for POSIX commands"

    # case 3: test with one command missing (using extremely unlikely name)
    result=$(
        __lib_require_cmds cat __nonexistent_cmd_f8a3b2c1__ 2>&1
    )
    __status=$?
    test_assert_eq 127 "${__status}" "__lib_require_cmds returns exit code 127 when one command is missing" "${__status}"

    printf "%s" "${result}" | grep -q "__nonexistent_cmd_f8a3b2c1__"
    test_assert_eq 0 "$?" "__lib_require_cmds error output contains missing command" "${__status}"

    # case 4: test with multiple missing commands
    result=$(
        __lib_require_cmds __missing_cmd_1__ __missing_cmd_2__ 2>&1
    )
    __status=$?
    test_assert_eq 127 "${__status}" "__lib_require_cmds returns exit code 127 for multiple missing commands" "${__status}"

    printf "%s" "${result}" | grep -q "__missing_cmd_1__"
    test_assert_eq 0 "$?" "__lib_require_cmds error contains first missing command" "${__status}"

    printf "%s" "${result}" | grep -q "__missing_cmd_2__"
    test_assert_eq 0 "$?" "__lib_require_cmds error contains second missing command" "${__status}"
}

test_require_cmds() {
    # case 1: test with all commands available (using POSIX-guaranteed commands)
    require_cmds cat test pwd > /dev/null 2>&1
    test_assert_eq 0 "$?" "require_cmds returns exit code 0 when all commands exist"

    # case 2: test with one missing command
    output=$(require_cmds cat __nonexistent_cmd_a7e5d9b3__ 2>&1)
    __status=$?

    test_assert_eq 127 "${__status}" "require_cmds returns exit code 127 for missing command" "${__status}"
    printf "%s" "${output}" | grep -q "__nonexistent_cmd_a7e5d9b3__"
    test_assert_eq 0 "$?" "require_cmds error output contains missing command" "${__status}"

    # case 3: test with mix of existing and non-existing commands
    output=$(require_cmds sh printf __missing_cmd_x9y2z8__ 2>&1)
    __status=$?

    test_assert_eq 127 "${__status}" "require_cmds returns exit code 127 with mixed commands" "${__status}"
    printf "%s" "${output}" | grep -q "__missing_cmd_x9y2z8__"
    test_assert_eq 0 "$?" "require_cmds identifies missing command among existing ones" "${__status}"
}

test_basename_strip_ext() {
    # case 1: test with space-separated input and .txt extension
    input="/a/b/foo.txt /a/b/bar.txt"
    expected="foo
bar"
    actual=$(basename_strip_ext "${input}" ".txt")
    test_assert_eq "${expected}" "${actual}" "basename_strip_ext strips extension .txt"

    # case 2: test with space-separated input and .1.md extension
    input="/a/b/foo.1.md /a/b/bar.1.md"
    expected="foo
bar"
    actual=$(basename_strip_ext "${input}" ".1.md")
    test_assert_eq "${expected}" "${actual}" "basename_strip_ext strips extension with dot in name"

    # case 3: test with newline-separated input and .txt extension
    input="/a/b/foo.txt\n/a/b/bar.txt"
    expected="foo
bar"
    actual=$(basename_strip_ext "${input}" ".txt")
    test_assert_eq "${expected}" "${actual}" "basename_strip_ext strips extension .txt with newlines"

    # case 4: test with empty input
    input=""
    expected=""
    actual=$(basename_strip_ext "${input}" ".txt" 2> /dev/null)
    __status=$?
    test_assert_neq 0 "${__status}" "basename_strip_ext returns exit code different from 0 for empty input" "${__status}"
    test_assert_eq "${expected}" "${actual}" "basename_strip_ext returns empty string for empty input" "${__status}"

    # case 5: test with no extension argument
    input="/a/b/foo.txt /a/b/bar.txt"
    expected=""
    actual=$(basename_strip_ext "${input}" "" 2> /dev/null)
    __status=$?
    test_assert_neq 0 "${__status}" "basename_strip_ext returns exit code different from 0 for no extension argument" "${__status}"
    test_assert_eq "${expected}" "${actual}" "basename_strip_ext returns basename without extension" "${__status}"

    # case 6: test with no input and no extension argument
    input=""
    expected=""
    actual=$(basename_strip_ext "${input}" "" 2> /dev/null)
    __status=$?
    test_assert_neq 0 "${__status}" "basename_strip_ext returns exit code different from 0 for no input and no extension argument" "${__status}"
    test_assert_eq "${expected}" "${actual}" "basename_strip_ext returns empty string for no input" "${__status}"
}

test_sanitize_to_lines() {
    # case 1: space-separated input without delimiter
    input="one two  three"
    expected="one
two
three"
    result=$(sanitize_to_lines "${input}")
    test_assert_eq "${expected}" "${result}" "space-separated input (default)"

    # case 2: comma-delimited input
    input="apple,banana, cherry , date"
    expected="apple
banana
cherry
date"
    result=$(sanitize_to_lines "${input}" ",")
    test_assert_eq "${expected}" "${result}" "comma-delimited input with spacing"

    # case 3: newline-delimited input
    input="foo\nbar\nbaz"
    expected="foo
bar
baz"
    result=$(sanitize_to_lines "${input}")
    test_assert_eq "${expected}" "${result}" "newline-separated input should pass unchanged"

    # case 4: empty input
    input=""
    expected=""
    result=$(sanitize_to_lines "${input}")
    test_assert_eq "${expected}" "${result}" "empty input returns nothing"

    # case 5: multiple spaces and tabs, no delimiter
    input=" a    b\tc   "
    expected="a
b	c"
    result=$(sanitize_to_lines "${input}")
    test_assert_eq "${expected}" "${result}" "multiple spaces and tabs are sanitized correctly"

    # case 6: input with only delimiters
    input=",,,"
    expected=""
    result=$(sanitize_to_lines "${input}" ",")
    test_assert_eq "${expected}" "${result}" "input with only delimiters returns nothing"

    # case 7: input with only spaces
    input="   "
    expected=""
    result=$(sanitize_to_lines "${input}")
    test_assert_eq "${expected}" "${result}" "input with only spaces returns nothing"

    # case 8: input with leading/trailing delimiters, mixed spaces and empty values
    input=",a,b, c,,d,"
    expected="a
b
c
d"
    result=$(sanitize_to_lines "${input}" ",")
    test_assert_eq "${expected}" "${result}" "input with leading/trailing delimiters and mixed spaces returns correct values"

    # case 9: mix of delimiters
    input="a, b c\nd"
    expected="a
b
c
d"
    mixed=$(sanitize_to_lines "${input}" " ,\\n")
    test_assert_eq "${expected}" "${mixed}" "input with mixed space/comma/newline as delimiters"

    # case 10: input with quoted values
    input="\"a b\", \"c d\", e"
    expected="\"a b\"
\"c d\"
e"
    result=$(sanitize_to_lines "${input}" ",")
    test_assert_eq "${expected}" "${result}" "input with quoted values returns correct values"

    # case 11: input with special characters
    # shellcheck disable=SC2016 # intentional: testing literal special chars including $
    input='a@b#c$d% ^&*()'
    # shellcheck disable=SC2016 # intentional: testing literal special chars including $
    expected='a@b#c$d%
^&*()'
    result=$(sanitize_to_lines "${input}")
    test_assert_eq "${expected}" "${result}" "input with special characters returns unchanged"

    # case 12: empty input with no delimiter
    input=""
    expected=""
    result=$(sanitize_to_lines "${input}")
    __status=$?
    test_assert_eq 0 "${__status}" "sanitize_to_lines returns exit code 0 for empty input" "${__status}"
    test_assert_eq "${expected}" "${result}" "empty input with no delimiter returns nothing" "${__status}"
}

test_log_functions() {
    log_output=$(
        (
            log INFO "info test"
            DEBUG=1 debug "debug test"
            info "info wrapper"
            warn "warn test"
            error "error test"
        ) 2>&1
    )

    printf "%s" "${log_output}" | grep -q '\[INFO\].*info test'
    test_assert_eq 0 "$?" "log INFO emits message"

    printf "%s" "${log_output}" | grep -q '\[DEBUG\].*debug test'
    test_assert_eq 0 "$?" "debug emits message"

    printf "%s" "${log_output}" | grep -q '\[INFO\].*info wrapper'
    test_assert_eq 0 "$?" "info emits message"

    printf "%s" "${log_output}" | grep -q '\[WARN\].*warn test'
    test_assert_eq 0 "$?" "warn emits message"

    printf "%s" "${log_output}" | grep -q '\[ERROR\].*error test'
    test_assert_eq 0 "$?" "error emits message"
}

test_die() {
    (
        die "fatal error" 7
    ) 2> /dev/null
    __status=$?
    test_assert_eq 7 "${__status}" "die exits with code 7" "${__status}"
}

test_list_diff() {
    # case 1: test with literal newlines
    list1="a
b
c"
    list2="b
c
d"
    expected="a
d"
    actual=$(list_diff "${list1}" "${list2}")
    test_assert_eq "${expected}" "${actual}" "list_diff symmetric difference (lists values separated by newlines)"

    # case 2: test with escaped newlines
    list1="a\nb\nc"
    list2="b\nc\nd"
    expected="a
d"
    actual=$(list_diff "${list1}" "${list2}")
    test_assert_eq "${expected}" "${actual}" "list_diff symmetric difference (lists values separated by \n)"

    # case 3: test with space-separated values
    list1="a b c"
    list2="b c d"
    expected="a
d"
    actual=$(list_diff "${list1}" "${list2}")
    test_assert_eq "${expected}" "${actual}" "list_diff symmetric difference (lists values separated by spaces)"

    # case 4: test with empty input
    list1=""
    list2=""
    expected=""
    actual=$(list_diff "${list1}" "${list2}")
    test_assert_eq "${expected}" "${actual}" "list_diff with empty input returns empty string"
}

test_capture_outputs() {
    # case 1: successful command with stdout only
    capture_outputs out err ret echo "hello world"
    # shellcheck disable=SC2154 # out/err/ret assigned by capture_outputs
    test_assert_eq "hello world" "${out}" "capture_outputs captures stdout"
    # shellcheck disable=SC2154 # out/err/ret assigned by capture_outputs
    test_assert_eq "" "${err}" "capture_outputs stderr is empty for stdout-only command"
    # shellcheck disable=SC2154 # out/err/ret assigned by capture_outputs
    test_assert_eq 0 "${ret}" "capture_outputs returns 0 for successful command"

    # case 2: command with stderr only
    capture_outputs out2 err2 ret2 sh -c 'echo "error message" >&2'
    # shellcheck disable=SC2154 # out2/err2/ret2 assigned by capture_outputs
    test_assert_eq "" "${out2}" "capture_outputs stdout is empty for stderr-only command"
    # shellcheck disable=SC2154 # out2/err2/ret2 assigned by capture_outputs
    test_assert_eq "error message" "${err2}" "capture_outputs captures stderr"
    # shellcheck disable=SC2154 # out2/err2/ret2 assigned by capture_outputs
    test_assert_eq 0 "${ret2}" "capture_outputs returns 0 for successful command with stderr"

    # case 3: command with both stdout and stderr
    capture_outputs out3 err3 ret3 sh -c 'echo "output"; echo "error" >&2'
    # shellcheck disable=SC2154 # out3/err3/ret3 assigned by capture_outputs
    test_assert_eq "output" "${out3}" "capture_outputs captures stdout with mixed output"
    # shellcheck disable=SC2154 # out3/err3/ret3 assigned by capture_outputs
    test_assert_eq "error" "${err3}" "capture_outputs captures stderr with mixed output"
    # shellcheck disable=SC2154 # out3/err3/ret3 assigned by capture_outputs
    test_assert_eq 0 "${ret3}" "capture_outputs returns 0 for successful mixed output"

    # case 4: failing command
    capture_outputs out4 err4 ret4 sh -c 'echo "failed"; exit 42'
    # shellcheck disable=SC2154 # out4/err4/ret4 assigned by capture_outputs
    test_assert_eq "failed" "${out4}" "capture_outputs captures stdout from failing command"
    # shellcheck disable=SC2154 # out4/err4/ret4 assigned by capture_outputs
    test_assert_eq 42 "${ret4}" "capture_outputs captures correct exit code" "${ret4}"

    # case 5: multiline output
    capture_outputs out5 err5 ret5 printf "line1\nline2\nline3"
    expected_multiline="line1
line2
line3"
    # shellcheck disable=SC2154 # out5/err5/ret5 assigned by capture_outputs
    test_assert_eq "${expected_multiline}" "${out5}" "capture_outputs handles multiline stdout"
    # shellcheck disable=SC2154 # out5/err5/ret5 assigned by capture_outputs
    test_assert_eq 0 "${ret5}" "capture_outputs returns 0 for multiline output"

    # case 6: empty output
    capture_outputs out6 err6 ret6 true
    # shellcheck disable=SC2154 # out6/err6/ret6 assigned by capture_outputs
    test_assert_eq "" "${out6}" "capture_outputs handles empty stdout"
    # shellcheck disable=SC2154 # out6/err6/ret6 assigned by capture_outputs
    test_assert_eq "" "${err6}" "capture_outputs handles empty stderr"
    # shellcheck disable=SC2154 # out6/err6/ret6 assigned by capture_outputs
    test_assert_eq 0 "${ret6}" "capture_outputs returns 0 for command with no output"
}

test_print_chars() {
    # case 1: basic character generation
    result1=$(print_chars "=" 10)
    test_assert_eq "==========" "${result1}" "print_chars creates 10 equal signs"

    # case 2: different character
    result2=$(print_chars "-" 5)
    test_assert_eq "-----" "${result2}" "print_chars creates 5 dashes"

    # case 3: single character
    result3=$(print_chars "*" 1)
    test_assert_eq "*" "${result3}" "print_chars creates 1 asterisk"

    # case 4: zero count (edge case)
    result4=$(print_chars "#" 0)
    test_assert_eq "" "${result4}" "print_chars creates empty string for count 0"
}

test_print_separator() {
    # case 1: default separator (80 chars, using __BLOCK_SEP_CHAR)
    output1=$(print_separator 2>&1)
    # Extract just the message part after [INFO]
    if [ "${__LOG_TIMESTAMPS}" -eq 1 ]; then
        result1=$(echo "${output1}" | grep '\[INFO\]' | cut -d']' -f4- | sed 's/^ *//')
    else
        result1=$(echo "${output1}" | grep '\[INFO\]' | cut -d']' -f3- | sed 's/^ *//')
    fi
    expected1=$(print_chars "-" 80)
    test_assert_eq "${expected1}" "${result1}" "print_separator creates default 80-char line"

    # case 2: custom separator character and width
    output2=$(print_separator "=" 40 2>&1)
    if [ "${__LOG_TIMESTAMPS}" -eq 1 ]; then
        result2=$(echo "${output2}" | grep '\[INFO\]' | cut -d']' -f4- | sed 's/^ *//')
    else
        result2=$(echo "${output2}" | grep '\[INFO\]' | cut -d']' -f3- | sed 's/^ *//')
    fi
    expected2=$(print_chars "=" 40)
    test_assert_eq "${expected2}" "${result2}" "print_separator creates custom 40-char line with ="

    # case 3: different character, default width
    output3=$(print_separator "*" 2>&1)
    if [ "${__LOG_TIMESTAMPS}" -eq 1 ]; then
        result3=$(echo "${output3}" | grep '\[INFO\]' | cut -d']' -f4- | sed 's/^ *//')
    else
        result3=$(echo "${output3}" | grep '\[INFO\]' | cut -d']' -f3- | sed 's/^ *//')
    fi
    expected3=$(print_chars "*" 80)
    test_assert_eq "${expected3}" "${result3}" "print_separator creates 80-char line with *"
}

test_print_section_header() {
    # case 1: basic header with default padding (= character, 80 chars)
    output1=$(print_section_header "Test Section" 2>&1)
    if [ "${__LOG_TIMESTAMPS}" -eq 1 ]; then
        result1=$(echo "${output1}" | grep '\[INFO\]' | cut -d']' -f4- | sed 's/^ *//')
    else
        result1=$(echo "${output1}" | grep '\[INFO\]' | cut -d']' -f3- | sed 's/^ *//')
    fi
    prefix1="= Test Section "
    padding1=$(print_chars "=" $((80 - ${#prefix1})))
    expected1="${prefix1}${padding1}"
    test_assert_eq "${expected1}" "${result1}" "print_section_header creates properly padded header"

    # case 2: custom character
    output2=$(print_section_header "Another Test" "-" 2>&1)
    if [ "${__LOG_TIMESTAMPS}" -eq 1 ]; then
        result2=$(echo "${output2}" | grep '\[INFO\]' | cut -d']' -f4- | sed 's/^ *//')
    else
        result2=$(echo "${output2}" | grep '\[INFO\]' | cut -d']' -f3- | sed 's/^ *//')
    fi
    prefix2="= Another Test "
    padding2=$(print_chars "-" $((80 - ${#prefix2})))
    expected2="${prefix2}${padding2}"
    test_assert_eq "${expected2}" "${result2}" "print_section_header works with custom character"

    # case 3: custom width
    output3=$(print_section_header "Short" "=" 30 2>&1)
    if [ "${__LOG_TIMESTAMPS}" -eq 1 ]; then
        result3=$(echo "${output3}" | grep '\[INFO\]' | cut -d']' -f4- | sed 's/^ *//')
    else
        result3=$(echo "${output3}" | grep '\[INFO\]' | cut -d']' -f3- | sed 's/^ *//')
    fi
    prefix3="= Short "
    padding3=$(print_chars "=" $((30 - ${#prefix3})))
    expected3="${prefix3}${padding3}"
    test_assert_eq "${expected3}" "${result3}" "print_section_header respects custom width"
}

test_print_section_banner() {
    # case 1: basic banner with default character (= character, 80 chars)
    output1=$(print_section_banner "Test Banner" 2>&1)

    # Extract the three log lines
    if [ "${__LOG_TIMESTAMPS}" -eq 1 ]; then
        lines1=$(echo "${output1}" | grep '\[INFO\]' | cut -d']' -f4- | sed 's/^ *//')
    else
        lines1=$(echo "${output1}" | grep '\[INFO\]' | cut -d']' -f3- | sed 's/^ *//')
    fi

    old_ifs=${IFS}
    IFS='
'
    # shellcheck disable=SC2086
    set -- ${lines1}
    IFS=${old_ifs}

    top_border1=$1
    title1=$2
    bottom_border1=$3

    expected_border1=$(print_chars "=" 80)
    test_assert_eq "${expected_border1}" "${top_border1}" "print_section_banner creates top border"
    test_assert_eq "Test Banner" "${title1}" "print_section_banner prints title"
    test_assert_eq "${expected_border1}" "${bottom_border1}" "print_section_banner creates bottom border"

    # case 2: custom character
    output2=$(print_section_banner "Custom Banner" "-" 2>&1)

    if [ "${__LOG_TIMESTAMPS}" -eq 1 ]; then
        lines2=$(echo "${output2}" | grep '\[INFO\]' | cut -d']' -f4- | sed 's/^ *//')
    else
        lines2=$(echo "${output2}" | grep '\[INFO\]' | cut -d']' -f3- | sed 's/^ *//')
    fi

    old_ifs=${IFS}
    IFS='
'
    # shellcheck disable=SC2086
    set -- ${lines2}
    IFS=${old_ifs}

    top_border2=$1
    title2=$2
    bottom_border2=$3

    expected_border2=$(print_chars "-" 80)
    test_assert_eq "${expected_border2}" "${top_border2}" "print_section_banner works with custom character (top)"
    test_assert_eq "Custom Banner" "${title2}" "print_section_banner prints custom title"
    test_assert_eq "${expected_border2}" "${bottom_border2}" "print_section_banner works with custom character (bottom)"

    # case 3: custom width
    output3=$(print_section_banner "Short" "=" 40 2>&1)

    if [ "${__LOG_TIMESTAMPS}" -eq 1 ]; then
        lines3=$(echo "${output3}" | grep '\[INFO\]' | cut -d']' -f4- | sed 's/^ *//')
    else
        lines3=$(echo "${output3}" | grep '\[INFO\]' | cut -d']' -f3- | sed 's/^ *//')
    fi

    old_ifs=${IFS}
    IFS='
'
    # shellcheck disable=SC2086
    set -- ${lines3}
    IFS=${old_ifs}

    top_border3=$1
    title3=$2
    bottom_border3=$3

    expected_border3=$(print_chars "=" 40)
    test_assert_eq "${expected_border3}" "${top_border3}" "print_section_banner respects custom width (top)"
    test_assert_eq "Short" "${title3}" "print_section_banner prints short title"
    test_assert_eq "${expected_border3}" "${bottom_border3}" "print_section_banner respects custom width (bottom)"
}

#
# run tests
#

require_cmds cut grep sed tr

# initialize test framework
test_init

# run
test_run "__collect_missing_cmds" test___collect_missing_cmds
test_run "__lib_require_cmds" test___lib_require_cmds

test_run "require_cmds" test_require_cmds
test_run "basename_strip_ext" test_basename_strip_ext
test_run "sanitize_to_lines" test_sanitize_to_lines
test_run "list_diff" test_list_diff
test_run "capture_outputs" test_capture_outputs
test_run "log functions" test_log_functions
test_run "die" test_die
test_run "print_chars" test_print_chars
test_run "print_separator" test_print_separator
test_run "print_section_header" test_print_section_header
test_run "print_section_banner" test_print_section_banner

# print test summary
test_summary
