#!/bin/sh
# Unit tests for lib.sh

# shellcheck disable=SC1091
. "${0%/*}/lib.sh"

test__collect_missing_cmds() {
	# case 1: test with all commands available
    result=$(__collect_missing_cmds echo grep sed)
    test_assert_eq "" "$result" "__collect_missing_cmds returns empty when all commands exist"

	# case 2: test with one command missing
    result=$(__collect_missing_cmds echo nonexistentcmd)
    test_assert_eq " nonexistentcmd" "$result" "__collect_missing_cmds detects one missing command"

	# case 3: test with multiple commands missing
    result=$(__collect_missing_cmds echo nonexistent1 printf nonexistent2)

    found_one=$(printf "%s" "$result" | grep -c "nonexistent1")
    test_assert_eq 1 "$found_one" "__collect_missing_cmds finds nonexistent1"
    found_two=$(printf "%s" "$result" | grep -c "nonexistent2")
    test_assert_eq 1 "$found_two" "__collect_missing_cmds finds nonexistent2"
}

test__lib_require_cmds() {
	# case 1: test with all commands available
	__lib_require_cmds echo grep sed >/dev/null 2>&1
	test_assert_eq 0 "$?" "__lib_require_cmds returns exit code 0 when all commands exist"

	# case 2: test with one command missing (run in subshell to avoid exiting the test runner)
	result=$(
		__lib_require_cmds echo nonexistentcmd 2>&1
	)
	status=$?
	test_assert_eq 127 "$status" "__lib_require_cmds returns exit code 127 when one command is missing" $status

	printf "%s" "$result" | grep -q "nonexistentcmd"
	test_assert_eq 0 "$?" "__lib_require_cmds error output contains missing command" $status
}

test_require_cmds() {
    # case 1: test with one missing command
    output=$(require_cmds echo nonexistentcmd 2>&1)
    status=$?
    
    test_assert_eq 127 "$status" "require_cmds returns exit code 127" $status
    printf "%s" "$output" | grep -q "nonexistentcmd"
    test_assert_eq 0 "$?" "require_cmds error output contains missing command" $status
}

test_basename_strip_ext() {
    # case 1: test with space-separated input and .txt extension
    input="/a/b/foo.txt /a/b/bar.txt"
    expected="foo
bar"
    actual=$(basename_strip_ext "$input" ".txt")
    test_assert_eq "$expected" "$actual" "basename_strip_ext strips extension .txt"

    # case 2: test with space-separated input and .1.md extension
    input="/a/b/foo.1.md /a/b/bar.1.md"
    expected="foo
bar"
    actual=$(basename_strip_ext "$input" ".1.md")
    test_assert_eq "$expected" "$actual" "basename_strip_ext strips extension with dot in name"

    # case 3: test with newline-separated input and .txt extension
    input="/a/b/foo.txt\n/a/b/bar.txt"
    expected="foo
bar"
    actual=$(basename_strip_ext "$input" ".txt")
    test_assert_eq "$expected" "$actual" "basename_strip_ext strips extension .txt with newlines"

    # case 4: test with empty input
    input=""
    expected=""
    # __err is used to capture stderr output but unused in this test
    capture_outputs actual __err status basename_strip_ext "$input" ".txt"
    test_assert_neq 0 "$status" "basename_strip_ext returns exit code different from 0 for empty input" "$status"
    test_assert_eq "$expected" "$actual" "basename_strip_ext returns empty string for empty input" "$status"

    # case 5: test with no extension argument
    input="/a/b/foo.txt /a/b/bar.txt"
    expected=""
    # __err is used to capture stderr output but unused in this test
    capture_outputs actual __err status basename_strip_ext "$input" ""
    test_assert_neq 0 "$status" "basename_strip_ext returns exit code different from 0 for no extension argument" "$status"
    test_assert_eq "$expected" "$actual" "basename_strip_ext returns basename without extension" "$status"

    # case 6: test with no input and no extension argument
    input=""
    expected=""
    # __err is used to capture stderr output but unused in this test
    capture_outputs actual __err status basename_strip_ext "$input" ""
    test_assert_neq 0 "$status" "basename_strip_ext returns exit code different from 0 for no input and no extension argument" "$status"
    test_assert_eq "$expected" "$actual" "basename_strip_ext returns empty string for no input" "$status"
}

test_sanitize_to_lines() {
    # case 1: space-separated input without delimiter
    input="one two  three"
    expected="one
two
three"
    result=$(sanitize_to_lines "$input")
    test_assert_eq "$expected" "$result" "space-separated input (default)"

    # case 2: comma-delimited input
    input="apple,banana, cherry , date"
    expected="apple
banana
cherry
date"
    result=$(sanitize_to_lines "$input" ",")
    test_assert_eq "$expected" "$result" "comma-delimited input with spacing"

    # case 3: newline-delimited input
    input="foo\nbar\nbaz"
    expected="foo
bar
baz"
    result=$(sanitize_to_lines "$input")
    test_assert_eq "$expected" "$result" "newline-separated input should pass unchanged"

    # case 4: empty input
    input=""
    expected=""
    result=$(sanitize_to_lines "$input")
    test_assert_eq "$expected" "$result" "empty input returns nothing"

    # case 5: multiple spaces and tabs, no delimiter
    input=" a    b\tc   "
    expected="a
b	c"
    result=$(sanitize_to_lines "$input")
    test_assert_eq "$expected" "$result" "multiple spaces and tabs are sanitized correctly"

    # case 6: input with only delimiters
    input=",,,"
    expected=""
    result=$(sanitize_to_lines "$input" ",")
    test_assert_eq "$expected" "$result" "input with only delimiters returns nothing"

    # case 7: input with only spaces
    input="   "
    expected=""
    result=$(sanitize_to_lines "$input")
    test_assert_eq "$expected" "$result" "input with only spaces returns nothing"

    # case 8: input with leading/trailing delimiters, mixed spaces and empty values
    input=",a,b, c,,d,"
    expected="a
b
c
d"
    result=$(sanitize_to_lines "$input" ",")
    test_assert_eq "$expected" "$result" "input with leading/trailing delimiters and mixed spaces returns correct values"

    # case 9: mix of delimiters
    input="a, b c\nd"
    expected="a
b
c
d"
    mixed=$(sanitize_to_lines "$input" " ,\\n")
    test_assert_eq "$expected" "$mixed" "input with mixed space/comma/newline as delimiters"

    # case 10: input with quoted values
    input="\"a b\", \"c d\", e"
    expected="\"a b\"
\"c d\"
e"
    result=$(sanitize_to_lines "$input" ",")
    test_assert_eq "$expected" "$result" "input with quoted values returns correct values"

    # case 11: input with special characters
    input="a@b#c$d% ^&*()"
    expected="a@b#c$d%
^&*()"
    result=$(sanitize_to_lines "$input")
    test_assert_eq "$expected" "$result" "input with special characters returns unchanged"

    # case 12: empty input with no delimiter
    input=""
    expected=""
    result=$(sanitize_to_lines "$input" >/dev/null)
    status=$?
    test_assert_eq 0 "$status" "sanitize_to_lines returns exit code 0 for empty input" $status
    test_assert_eq "$expected" "$result" "empty input with no delimiter returns nothing" $status
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

    printf "%s" "$log_output" | grep -q '\[INFO\].*info test'
    test_assert_eq 0 "$?" "log INFO emits message"

    printf "%s" "$log_output" | grep -q '\[DEBUG\].*debug test'
    test_assert_eq 0 "$?" "debug emits message"

    printf "%s" "$log_output" | grep -q '\[INFO\].*info wrapper'
    test_assert_eq 0 "$?" "info emits message"

    printf "%s" "$log_output" | grep -q '\[WARN\].*warn test'
    test_assert_eq 0 "$?" "warn emits message"

    printf "%s" "$log_output" | grep -q '\[ERROR\].*error test'
    test_assert_eq 0 "$?" "error emits message"
}

test_die() {
    (
        die "fatal error" 7
    ) 2>/dev/null
    status=$?
    test_assert_eq 7 "$status" "die exits with code 7" "$status"
}

test_print_script_start() {
    # case 1: test with default separator
    title="Test Start Block"
    sep_char="-" # default separator

    # trigger both print and trap
    output=$(
        (
            print_script_start "$title"
            : # no-op to ensure the trap runs
        ) 2>&1
    )

    # expected lines
    expected_header="${sep_char}${sep_char}${sep_char} ${title} ${sep_char}${sep_char}${sep_char}"
    expected_bottom=$(printf "%${#expected_header}s" "" | tr ' ' "$sep_char")

    # extract the two log lines
    info_lines=$(echo "$output" | grep '\[INFO\]' | cut -d']' -f4- | sed 's/^ *//')

    old_ifs=$IFS
    IFS='
'
    # shellcheck disable=SC2086
    set -- $info_lines
    IFS=$old_ifs

    actual_header=$1
    actual_bottom=$2

    test_assert_eq "$expected_header" "$actual_header" "print_script_start prints header with title (default sep)"
    test_assert_eq "$expected_bottom" "$actual_bottom" "print_script_start prints bottom of correct length (default sep)"

    # case 2: test with custom separator
    sep_char="#"
    set_print_block_sep "$sep_char"
    output=$(
        (
            print_script_start "$title"
            : # no-op to ensure the trap runs
        ) 2>&1
    )

    # expected lines
    expected_header="${sep_char}${sep_char}${sep_char} ${title} ${sep_char}${sep_char}${sep_char}"
    expected_bottom=$(printf "%${#expected_header}s" "" | tr ' ' "$sep_char")

    # extract the two log lines
    info_lines=$(echo "$output" | grep '\[INFO\]' | cut -d']' -f4- | sed 's/^ *//')

    old_ifs=$IFS
    IFS='
'
    # shellcheck disable=SC2086
    set -- $info_lines
    IFS=$old_ifs

    actual_header=$1
    actual_bottom=$2

    test_assert_eq "$expected_header" "$actual_header" "print_script_start prints header with title (custom sep)"
    test_assert_eq "$expected_bottom" "$actual_bottom" "print_script_start prints bottom of correct length (custom sep)"
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
    actual=$(list_diff "$list1" "$list2")
    test_assert_eq "$expected" "$actual" "list_diff symmetric difference (lists values separated by newlines)"

	# case 2: test with escaped newlines
    list1="a\nb\nc"
    list2="b\nc\nd"
    expected="a
d"
    actual=$(list_diff "$list1" "$list2")
    test_assert_eq "$expected" "$actual" "list_diff symmetric difference (lists values separated by \n)"

	# case 3: test with space-separated values
	list1="a b c"
	list2="b c d"
	expected="a
d"
	actual=$(list_diff "$list1" "$list2")
	test_assert_eq "$expected" "$actual" "list_diff symmetric difference (lists values separated by spaces)"

    # case 4: test with empty input
    list1=""
    list2=""
    expected=""
    actual=$(list_diff "$list1" "$list2")
    test_assert_eq "$expected" "$actual" "list_diff with empty input returns empty string"
}

#
# run tests
#

require_cmds cut grep sed tr

# initialize test framework
test_init

# run
test_run "__collect_missing_cmds" test__collect_missing_cmds
test_run "__lib_require_cmds" test__lib_require_cmds

test_run "require_cmds" test_require_cmds
test_run "basename_strip_ext" test_basename_strip_ext
test_run "sanitize_to_lines" test_sanitize_to_lines
test_run "list_diff" test_list_diff
test_run "log functions" test_log_functions
test_run "die" test_die
test_run "print_script_start" test_print_script_start

# print test summary
test_summary
