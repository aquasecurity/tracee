#!/usr/bin/env bash

# assert_success asserts that the test subject has succeeded
assert_success() {
    [ "$status" -eq 0 ]
}

# assert_failure asserts that the test subject has failed
assert_failure() {
    [ "$status" -ne 0 ]
}

# assert_contains asserts that the text in $1 is contained in the output of the test subject
# if $2 is provided and points to a file, this file is used
# text in $1 can be a (simple grep) regexp
assert_contains() {
  if [ -f "$2" ]; then
    grep -q "$1" "$2"
  else
    grep -q "$1" <<<"$output"
  fi
}

# assert_absent asserts that the text in $1 is not contained in the output of the test subject
# if $2 is provided and points to a file, this file is used
# text in $1 can be a (simple grep) regexp
assert_absent() {
  if [ -f "$2" ]; then
    grep -qv "$1" "$2"
  else
    grep -qv "$1" <<<"$output"
  fi
}
