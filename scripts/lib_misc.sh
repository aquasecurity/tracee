#!/bin/sh

#
# misc
#

__LIB_MISC_NAME="lib_misc.sh"

# prevent multiple sourcing
if [ -n "${__LIB_MISC_SH_SOURCED:-}" ]; then
    return 0
fi
__LIB_MISC_SH_SOURCED=1

# must be sourced, not executed
case "${0##*/}" in
    "${__LIB_MISC_NAME}")
        printf "[%s]: %s\n" "${__LIB_MISC_NAME}" "This script must be sourced, not executed."
        exit 1
        ;;
esac

############
# functions
############

# die logs an error message and exits with a given code (default: 1).
#
# $1: MESSAGE - Error message to log.
# $2: CODE - Exit code (default: 1).
#
# Usage:
#   die MESSAGE [CODE]
#
# Example:
#   die "This is a fatal error." 127
#
# Output:
#   [1970-01-01T00:00:00.000000Z] [script_name] [ERROR] This is a fatal error.
#   Exits with code 127.
die() {
    die_msg="$1"
    die_code="${2:-1}"
    if [ -z "${die_msg}" ]; then
        __error "die: No MESSAGE provided"
        return 1
    fi

    error "${die_msg}"
    exit "${die_code}"
}

# require_cmds checks for required commands and exits if any are missing (error code 127).
#
# $@: CMD1 CMD2... - List of commands to check.
#
# Usage:
#   require_cmds CMD1 CMD2...
#
# Example:
#   require_cmds git grep sed
require_cmds() {
    if [ -z "$1" ]; then
        __error "require_cmds: No CMD provided"
        return 1
    fi

    require_cmds_missing="$(__collect_missing_cmds "$@")" || {
        __status=$?
        __error "require_cmds: Failed to collect missing commands"
        return ${__status}
    }

    if [ -n "${require_cmds_missing}" ]; then
        error "The following required command(s) are missing:${require_cmds_missing}"
        die "Please install the missing dependencies and try again." 127 || {
            __status=$?
            __error "require_cmds: Failed to die"
            return ${__status}
        }
    fi
}

# basename_strip_ext extracts basenames from filenames by removing the given extension.
#
# $1: FILES - List of filenames.
# $2: EXTENSION - File extension to remove.
#
# Usage:
#   basename_strip_ext FILES EXTENSION
#
# Example:
#   basename_strip_ext "path/file1.txt path/file2.txt" ".txt"
#
# Output:
#   file1
#   file2
basename_strip_ext() {
    basename_strip_ext_files=$(sanitize_to_lines "$1")
    basename_strip_ext_ext="$2"
    basename_strip_ext_ext="${basename_strip_ext_ext#.}" # remove leading dot if present
    if [ -z "${basename_strip_ext_files}" ]; then
        __error "basename_strip_ext: No FILES provided"
        return 1
    fi
    if [ -z "${basename_strip_ext_ext}" ]; then
        __error "basename_strip_ext: No EXTENSION provided"
        return 1
    fi

    # step 1: extract basenames
    basename_strip_ext_step1=$(printf "%s\n" "${basename_strip_ext_files}" | xargs -n1 basename) || {
        __status=$?
        __error "basename_strip_ext: xargs extract basename failed"
        return ${__status}
    }

    # step 2: remove extension
    basename_strip_ext_result=$(printf "%s\n" "${basename_strip_ext_step1}" | sed "s/\.${basename_strip_ext_ext}\$//") || {
        __status=$?
        __error "basename_strip_ext: sed remove extension failed"
        return ${__status}
    }

    printf "%s\n" "${basename_strip_ext_result}"
}

# sanitize_to_lines converts a delimited string to a cleaned list of lines.
# Steps:
#   - Interprets input as printf %b (so \n becomes newline),
#   - Splits by the specified delimiter (default: space),
#   - Trims whitespace and removes empty lines.
#
# $1: INPUT - Input string to sanitize.
# $2: DELIMITER - Delimiter to split the input string (default: space).
#
# Usage:
#   sanitize_to_lines INPUT [DELIMITER]
#
# Example1:
#   sanitize_to_lines "apple banana cherry date"
#   sanitize_to_lines "apple,banana, cherry , date" ","
#   sanitize_to_lines "apple\nbanana\ncherry\ndate"
#
# Output1:
#   apple
#   banana
#   cherry
#   date
sanitize_to_lines() {
    sanitize_to_lines_input=$1
    sanitize_to_lines_delimiter=$2
    if [ -z "${sanitize_to_lines_input}" ]; then
        # do not error if no input is provided
        return 0
    fi
    if [ -z "${sanitize_to_lines_delimiter}" ]; then
        sanitize_to_lines_delimiter=" "
    fi

    # step 1: convert input into lines
    sanitize_to_lines_step1=$(printf "%b" "${sanitize_to_lines_input}" | tr "${sanitize_to_lines_delimiter}" '\n') || {
        __status=$?
        __error "sanitize_to_lines: tr failed"
        return ${__status}
    }

    # step 2: trim leading/trailing whitespace
    sanitize_to_lines_step2=$(printf "%s\n" "${sanitize_to_lines_step1}" | sed 's/^[[:space:]]*//;s/[[:space:]]*$//') || {
        __status=$?
        __error "sanitize_to_lines: sed trim failed"
        return ${__status}
    }

    # step 3: remove empty lines
    sanitize_to_lines_result=$(printf "%s\n" "${sanitize_to_lines_step2}" | sed '/^$/d') || {
        __status=$?
        __error "sanitize_to_lines: sed remove empty lines failed"
        return ${__status}
    }

    # output result
    printf "%s\n" "${sanitize_to_lines_result}"
}

# list_diff computes the symmetric difference between two lists.
# That is, it prints items that are only in A or only in B.
#
# $1: LIST_A - First list of items (space, comma, or newline separated).
# $2: LIST_B - Second list of items (space, comma, or newline separated).
#
# Usage:
#   list_diff LIST_A LIST_B
#
# Example:
#   list_diff "a\nb\nc" "b\nc\nd"
#   list_diff "a b c" "b c d"
#   list_diff "a,b,c" "b,c,d"
#
# Output:
#   a
#   d
list_diff() {
    list_diff_list_a="$1"
    list_diff_list_b="$2"

    list_diff_list_a_step1=$(sanitize_to_lines "${list_diff_list_a}") || {
        __status=$?
        __error "list_diff: sanitize_to_lines LIST_A failed"
        return ${__status}
    }
    list_diff_list_b_step1=$(sanitize_to_lines "${list_diff_list_b}") || {
        __status=$?
        __error "list_diff: sanitize_to_lines LIST_B failed"
        return ${__status}
    }
    list_diff_sanitized_a=$(printf "%s\n" "${list_diff_list_a_step1}" | sort -u) # sort assumed not to fail
    list_diff_sanitized_b=$(printf "%s\n" "${list_diff_list_b_step1}" | sort -u) # sort assumed not to fail

    # a not in b
    while IFS= read -r a; do
        match_found=0
        while IFS= read -r b; do
            if [ "${a}" = "${b}" ]; then
                match_found=1
                break
            fi
        done << EOF
${list_diff_sanitized_b}
EOF

        # if no match found, print the item
        if [ "${match_found}" -eq 0 ]; then
            printf '%s\n' "${a}"
        fi
    done << EOF
${list_diff_sanitized_a}
EOF
    : # guard set -e on empty input

    # b not in a
    while IFS= read -r b; do
        match_found=0
        while IFS= read -r a; do
            if [ "${b}" = "${a}" ]; then
                match_found=1
                break
            fi
        done << EOF
${list_diff_sanitized_a}
EOF

        # if no match found, print the item
        if [ "${match_found}" -eq 0 ]; then
            printf '%s\n' "${b}"
        fi
    done << EOF
${list_diff_sanitized_b}
EOF
    : # guard set -e on empty input
}

# next_available_fd finds the next available file descriptor (FD) number.
# It scans the /proc/self/fd directory to find the highest used FD and returns the next available one.
#
# Usage:
#   next_available_fd
#
# Example:
#   echo $(next_available_fd)
#
# Output:
#   3 # if 2 is the highest used FD
next_available_fd() {
    max_fd=2

    for fd_path in /proc/self/fd/*; do
        fd=${fd_path##*/}

        # ensure $fd is a valid integer
        case ${fd} in
            '' | *[!0-9]*) continue ;;
        esac

        if [ "${fd}" -gt "${max_fd}" ]; then
            max_fd=${fd}
        fi
    done

    printf '%s\n' "$((max_fd + 1))"
}

# verify_gpg_signature verifies a file's GPG signature using a provided public key.
# Creates a temporary GPG home directory, imports the key, verifies the signature, and cleans up.
#
# $1: ARCHIVE_FILE - Path to the file to verify.
# $2: SIGNATURE_FILE - Path to the detached signature file (.sig).
# $3: PUBLIC_KEY_FILE - Path to the GPG public key file (.asc or .gpg).
# $4: DESCRIPTION - Optional description for log messages (default: "file").
#
# Usage:
#   verify_gpg_signature ARCHIVE_FILE SIGNATURE_FILE PUBLIC_KEY_FILE [DESCRIPTION]
#
# Example:
#   verify_gpg_signature "awscliv2.zip" "awscliv2.zip.sig" "aws-cli-public-key.asc" "AWS CLI"
#
# Returns:
#   0 if signature verification succeeds, non-zero on failure.
verify_gpg_signature() {
    verify_gpg_signature_archive="$1"
    verify_gpg_signature_sig="$2"
    verify_gpg_signature_key="$3"
    verify_gpg_signature_desc="${4:-file}"
    verify_gpg_signature_home=""
    verify_gpg_signature_status=0

    if [ -z "${verify_gpg_signature_archive}" ]; then
        __error "verify_gpg_signature: No ARCHIVE_FILE provided"
        return 1
    fi
    if [ -z "${verify_gpg_signature_sig}" ]; then
        __error "verify_gpg_signature: No SIGNATURE_FILE provided"
        return 1
    fi
    if [ -z "${verify_gpg_signature_key}" ]; then
        __error "verify_gpg_signature: No PUBLIC_KEY_FILE provided"
        return 1
    fi

    # Check that required files exist
    if [ ! -f "${verify_gpg_signature_archive}" ]; then
        __error "verify_gpg_signature: Archive file not found: ${verify_gpg_signature_archive}"
        return 1
    fi
    if [ ! -f "${verify_gpg_signature_sig}" ]; then
        __error "verify_gpg_signature: Signature file not found: ${verify_gpg_signature_sig}"
        return 1
    fi
    if [ ! -f "${verify_gpg_signature_key}" ]; then
        __error "verify_gpg_signature: Public key file not found: ${verify_gpg_signature_key}"
        return 1
    fi

    info "Verifying ${verify_gpg_signature_desc} signature..."

    # Create a temporary directory for GPG keyring
    verify_gpg_signature_home="$(mktemp -d)" || {
        __error "verify_gpg_signature: Failed to create temporary directory"
        return 1
    }

    # Import the public key into temporary keyring
    if ! gpg \
        --homedir "${verify_gpg_signature_home}" \
        --batch \
        --quiet \
        --import "${verify_gpg_signature_key}" 2> /dev/null; then
        __error "verify_gpg_signature: Failed to import GPG public key"
        rm -rf "${verify_gpg_signature_home}"
        return 1
    fi

    # Verify the signature
    if gpg \
        --homedir "${verify_gpg_signature_home}" \
        --batch \
        --verify \
        "${verify_gpg_signature_sig}" \
        "${verify_gpg_signature_archive}" 2> /dev/null; then
        info "${verify_gpg_signature_desc} signature verification succeeded"
        verify_gpg_signature_status=0
    else
        error "${verify_gpg_signature_desc} signature verification FAILED"
        error "The downloaded archive may have been tampered with"
        verify_gpg_signature_status=1
    fi

    # Cleanup GPG home directory
    rm -rf "${verify_gpg_signature_home}"
    return "${verify_gpg_signature_status}"
}

# verify_sha256_checksum verifies a file's SHA256 checksum against an expected value.
#
# $1: TARGET_FILE - Path to the file to verify.
# $2: EXPECTED_CHECKSUM - Expected SHA256 checksum (64 hex characters) or path to checksum file.
# $3: DESCRIPTION - Optional description for log messages (default: "file").
#
# Usage:
#   verify_sha256_checksum TARGET_FILE EXPECTED_CHECKSUM [DESCRIPTION]
#
# Example:
#   verify_sha256_checksum "runner.tar.gz" "abc123..." "GitHub Actions Runner"
#   verify_sha256_checksum "runner.tar.gz" "runner.tar.gz.sha256" "GitHub Actions Runner"
#
# Returns:
#   0 if checksum verification succeeds, non-zero on failure.
verify_sha256_checksum() {
    verify_sha256_file="$1"
    verify_sha256_expected="$2"
    verify_sha256_desc="${3:-file}"
    verify_sha256_computed=""

    if [ -z "${verify_sha256_file}" ]; then
        __error "verify_sha256_checksum: No TARGET_FILE provided"
        return 1
    fi
    if [ -z "${verify_sha256_expected}" ]; then
        __error "verify_sha256_checksum: No EXPECTED_CHECKSUM provided"
        return 1
    fi

    # Check that the target file exists
    if [ ! -f "${verify_sha256_file}" ]; then
        __error "verify_sha256_checksum: Target file not found: ${verify_sha256_file}"
        return 1
    fi

    # If expected is a file path, read the checksum from it
    if [ -f "${verify_sha256_expected}" ]; then
        # Checksum file format: "checksum  filename" or just "checksum"
        verify_sha256_expected=$(awk '{print $1}' "${verify_sha256_expected}") || {
            __error "verify_sha256_checksum: Failed to read checksum file"
            return 1
        }
    fi

    info "Verifying ${verify_sha256_desc} checksum..."

    # Compute the SHA256 checksum - try shasum first (macOS), then sha256sum (Linux)
    if command -v shasum > /dev/null 2>&1; then
        verify_sha256_computed=$(shasum -a 256 "${verify_sha256_file}" | awk '{print $1}') || {
            __error "verify_sha256_checksum: Failed to compute checksum with shasum"
            return 1
        }
    elif command -v sha256sum > /dev/null 2>&1; then
        verify_sha256_computed=$(sha256sum "${verify_sha256_file}" | awk '{print $1}') || {
            __error "verify_sha256_checksum: Failed to compute checksum with sha256sum"
            return 1
        }
    else
        __error "verify_sha256_checksum: No SHA256 tool found (need shasum or sha256sum)"
        return 1
    fi

    # Compare checksums (case-insensitive)
    verify_sha256_expected_lower=$(printf '%s' "${verify_sha256_expected}" | tr '[:upper:]' '[:lower:]')
    verify_sha256_computed_lower=$(printf '%s' "${verify_sha256_computed}" | tr '[:upper:]' '[:lower:]')

    if [ "${verify_sha256_computed_lower}" = "${verify_sha256_expected_lower}" ]; then
        info "${verify_sha256_desc} checksum verification succeeded"
        return 0
    else
        error "${verify_sha256_desc} checksum verification FAILED"
        error "Expected: ${verify_sha256_expected}"
        error "Computed: ${verify_sha256_computed}"
        return 1
    fi
}

# capture_outputs captures the outputs of a command (stdout, stderr and return value) into variables.
# It uses temporary files to store the outputs and ensures that the files are cleaned up afterwards.
# The captured outputs are then assigned to the original variables.
#
# $1: STDOUT_VAR - Variable name for capturing stdout.
# $2: STDERR_VAR - Variable name for capturing stderr.
# $3: RET_VAL_VAR - Variable name for capturing the return value.
# $4: COMMAND... - Command to execute and capture outputs from.
#
# Usage:
#   capture_outputs STDOUT_VAR STDERR_VAR RET_VAL_VAR COMMAND...
#
# Example:
#   capture_outputs my_stdout_var my_stderr_var my_ret_val_var ls -l
#
# Output:
#   my_stdout_var: Captured stdout from the command.
#   my_stderr_var: Captured stderr from the command.
#   my_ret_val_var: Captured return value from the command.
capture_outputs() {
    capture_outputs_out_var=$1
    capture_outputs_err_var=$2
    capture_outputs_ret_val_var=$3
    shift 3

    if [ -z "${capture_outputs_out_var}" ]; then
        __error "capture_outputs: No STDOUT_VAR provided"
        return 1
    fi
    if [ -z "${capture_outputs_err_var}" ]; then
        __error "capture_outputs: No STDERR_VAR provided"
        return 1
    fi
    if [ -z "${capture_outputs_ret_val_var}" ]; then
        __error "capture_outputs: No RET_VAL_VAR provided"
        return 1
    fi

    capture_outputs_tmp_out=$(mktemp) || {
        __error "capture_outputs: Failed to create tmp file for stdout"
        return 1
    }
    capture_outputs_tmp_err=$(mktemp) || {
        __error "capture_outputs: Failed to create tmp file for stderr"
        rm -f "${capture_outputs_tmp_out}"
        return 1
    }

    capture_outputs_ret_val_tmp=0
    # shellcheck disable=SC2034 # used indirectly
    "$@" > "${capture_outputs_tmp_out}" 2> "${capture_outputs_tmp_err}" || capture_outputs_ret_val_tmp=$?

    # shellcheck disable=SC2034 # used indirectly
    capture_outputs_out_var_tmp=$(cat "${capture_outputs_tmp_out}") || {
        __error "capture_outputs: Failed to read stdout from tmp file"
        rm -f "${capture_outputs_tmp_out}" "${capture_outputs_tmp_err}"
        return 1
    }
    # shellcheck disable=SC2034 # used indirectly
    capture_outputs_err_var_tmp=$(cat "${capture_outputs_tmp_err}") || {
        __error "capture_outputs: Failed to read stderr from tmp file"
        rm -f "${capture_outputs_tmp_out}" "${capture_outputs_tmp_err}"
        return 1
    }

    rm -f "${capture_outputs_tmp_out}" "${capture_outputs_tmp_err}" || {
        __error "capture_outputs: Failed to remove tmp files"
        return 1
    }

    eval "${capture_outputs_out_var}=\"\${capture_outputs_out_var_tmp}\"" || {
        __error "capture_outputs: Failed to assign stdout to ${capture_outputs_out_var}"
        return 1
    }
    eval "${capture_outputs_err_var}=\"\${capture_outputs_err_var_tmp}\"" || {
        __error "capture_outputs: Failed to assign stderr to ${capture_outputs_err_var}"
        return 1
    }
    eval "${capture_outputs_ret_val_var}=\${capture_outputs_ret_val_tmp}" || {
        __error "capture_outputs: Failed to assign return value to ${capture_outputs_ret_val_var}"
        return 1
    }

    return 0
}
