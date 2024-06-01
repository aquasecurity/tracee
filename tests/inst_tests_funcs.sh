ARCH=$(uname -m)

TRACEE_STARTUP_TIMEOUT=30
TRACEE_SHUTDOWN_TIMEOUT=30
TRACEE_RUN_TIMEOUT=60
SCRIPT_TMP_DIR=/tmp/analyze_test
TRACEE_TMP_DIR=/tmp/tracee

TESTS_DIR="$SCRIPT_DIR/e2e-inst-signatures/scripts"

KERNEL=$(uname -r)

info_exit() {
    echo -n "INFO: "
    echo "$@"
    exit 0
}

info() {
    echo -n "INFO: "
    echo "$@"
}

error_exit() {
    echo -n "ERROR: "
    echo "$@"
    exit 1
}

print_environment() {
	info
	info "= ENVIRONMENT ================================================="
	info
	info "KERNEL: ${KERNEL}"
	info "CLANG: $(clang --version)"
	info "GO: $(go version)"
}

compile_tracee() {
	info
	info "= COMPILING TRACEE ============================================"
	info
	# make clean # if you want to be extra cautious
	set -e
	make -j"$(nproc)" all
	make e2e-inst-signatures "$@"
	set +e

	# Check if tracee was built correctly

	if [[ ! -x ./dist/tracee ]]; then
		error_exit "could not find tracee executable"
	fi
}

# Function: run_tracee
# Description:
#	Runs the tracee program with the specified events and flags.
#	Assumes that runs from Tracee's root directory.
# Parameters:
#   - events: The events to trace.
#   - flags: Additional flags to pass to the tracee program.
#   - output_file: The output file to save the tracee logs. If not provided, the default file will be used.
#   - logfile: The logfile to save the tracee logs. If not provided, the default logfile will be used.
# Returns: None
run_tracee() {
	local events=$1
	local output_file=$2
	local logfile=$3
	local sig_dir=$4
	local flags=$5
	
	rm -f $output_file
	rm -f $logfile
	./dist/tracee \
		--install-path $TRACEE_TMP_DIR \
		--cache cache-type=mem \
		--cache mem-cache-size=512 \
		--proctree source=both \
		--output option:sort-events \
		--output json:$output_file \
		--log file:$logfile \
		--log debug \
		--signatures-dir "$sig_dir" \
		--scope comm=echo,mv,ls,tracee,proctreetester,ping,ds_writer,fsnotify_tester,process_execute,tracee-ebpf,writev,set_fs_pwd.sh \
		--dnscache enable \
		--grpc-listen-addr unix:/tmp/tracee.sock \
		--events "$events" \
		$flags &
}

# Function: wait_for_tracee
#
# Description:
#   This function waits for the Tracee process to start by checking the existence of the tracee.pid file in the TRACEE_TMP_DIR.
#   It waits for a maximum of TRACEE_STARTUP_TIMEOUT seconds for the Tracee process to start.
#   If the Tracee process starts within the timeout period, it prints a success message and returns.
#   If the Tracee process fails to start within the timeout period, it prints an error message and returns with a non-zero exit code.
#
# Parameters:
#   - logfile: The path to the log file where the error messages will be written.
#
# Returns:
#   0 if the Tracee process starts successfully
#   1 if the Tracee process fails to start within the timeout period
wait_for_tracee() {
	local logfile=$1
	times=0
	timedout=0
	while true; do
		times=$((times + 1))
		sleep 1
		if [[ -f $TRACEE_TMP_DIR/tracee.pid ]]; then
			info
			info "UP AND RUNNING"
			info
			break
		fi

		if [[ $times -gt $TRACEE_STARTUP_TIMEOUT ]]; then
			timedout=1
			break
		fi
	done

	# Tracee failed to start
	if [[ $timedout -eq 1 ]]; then
		info
		info "$TEST: FAILED. ERRORS:"
		info
		cat $logfile

		return 1
	fi

	# Allow tracee to start processing events
	sleep 3
}

# Function: check_test
# Description: Checks if a test has failed or not. If the test has failed, it prints the stderr from tracee.
# Parameters: 
#   - test: The name of the test to check.
#   - logfiles_raw: The logfiles to check, seperated by spaces.
#   - events_file: The file containing the events to check.
# Returns: 0 if the test is successful, 1 if the test fails
check_test() {
	local test=$1
	local logfiles_raw=$2
	local events_file=$3

	# Split the string into an array
    IFS=' ' read -r -a logfiles <<< "$logfiles_raw"


	# Check if the test has failed or not
	found=0
	errors=0
	if [[ -f $events_file ]]; then
		cat $events_file | jq .eventName | grep -q "$test" && found=1
	else
		found=1
	fi
	

	for logfile in "${logfiles[@]}"; do
		errors=$(($errors + $(grep -cE "ERROR|FATAL" $logfile)))
	done

	if [[ $test == "BPF_ATTACH" ]]; then
		errors=0
	fi

	info
	if [[ $found -eq 1 && $errors -eq 0 ]]; then
		info "$test: SUCCESS"
	else
		info "$test: FAILED"
		if [[ $found -ne 1 ]]; then
			info "No events found for $test"
		fi
		if [[ $errors -ne 0 ]]; then
			info "Errors found in logfiles"
		fi
		info "logs from tracee:"
		for logfile in "${logfiles[@]}"; do
			info "LOGFILE $logfile:"
			if [[ ! -s "$logfile" ]]; then
				info "No log from logfile $logfile"
			else
				cat "$logfile"
			fi
		done
		info
		return 1
	fi
	info
}

# Function: kill_tracee
# Description: Kills the tracee process to ensure it is exited and can be started again.
# Parameters: None
# Returns: None
kill_tracee() {
	pid_tracee=$(pidof tracee | cut -d' ' -f1)
	if [[ -z "$pid_tracee" ]]; then
		return
	fi
	kill -SIGINT "$pid_tracee"
	sleep $TRACEE_SHUTDOWN_TIMEOUT
	kill -SIGKILL "$pid_tracee" >/dev/null 2>&1
	sleep 3
}

# Function: cleanup
# Description: Cleans up any leftovers from the test.
# Parameters: None
# Returns: None
cleanup() {
	rm -rf $SCRIPT_TMP_DIR
	rm -rf $TRACEE_TMP_DIR
}

# Some tests might need special setup (like running before tracee)
special_tests_setup() {
	local test=$1
	local skip=0
	case $test in
	HOOKED_SYSCALL)
		if [[ ! -d /lib/modules/${KERNEL}/build ]]; then
			info "skip hooked_syscall test, no kernel headers"
			skip=1
		elif [[ "$KERNEL" == *"amzn"* ]]; then
			info "skip hooked_syscall test in amazon linux"
			skip=1
		elif [[ $ARCH == "aarch64" ]]; then
			info "skip hooked_syscall test in aarch64"
			skip=1
		elif [[ "$VERSION_CODENAME" == "mantic" ]]; then
			# https://github.com/aquasecurity/tracee/issues/3628
			info "skip hooked_syscall in mantic 6.5 kernel, broken"
			skip=1
		else
			"${TESTS_DIR}"/hooked_syscall.sh
		fi
		;;
	esac
	return $skip
}

# Function to run a specific test.
# Parameters:
#   - test: The name of the test to run.
# Returns: None.
run_test() {
	local test=$1

	# Check the type of test.
	case $test in
		HOOKED_SYSCALL)
			# If the test is HOOKED_SYSCALL, wait for the tracee hooked event to be processed.
			sleep 15
			;;
		*)
			# For other tests, run the corresponding script with a timeout.
			timeout --preserve-status $TRACEE_RUN_TIMEOUT "${TESTS_DIR}"/"${test,,}".sh
			;;
	esac
}

# Define the function
extract_events_from_signature_file() {
    local file="$1"
    local matches

	# Use grep to find all matches and print the match group
	matches=$(grep -oP 'Source:\s+"tracee",\s+Name:\s+"(.*?)"' "$file" | awk -F 'Name: "' '{print $2}' | awk -F '"' '{print $1}')

    # Convert matches to a slice format
    local slice=""
    for match in $matches; do
        slice+="$match,"
    done

    # Remove the trailing comma and space, then add the closing brace
    slice=${slice%,}

    # Print the resulting slice
    echo "$slice"
}

find_signature_file() {
    local directory="$1"
    local signature_name="$2"
    local file

    # Search for the string in files within the directory
    file=$(grep -rl "\"$signature_name\"" "$directory")

    # Check if a file was found
    if [ -n "$file" ]; then
        # Return the path of the first file found
        echo "$file"
    else
        # If no file was found, print an error message
        echo "No file contains the string: $signature_name"
        return 1
    fi
}

remove_sig_from_export() {
	local signature_file="$1"
	local signature_dir="$2"

	# Get the name of the type created in the Go file
	type_name=$(grep -oP '(?<=type )e2e\w+' "$signature_file" | head -n 1)

	# Remove the line that initializes the type in export.go
	sed -i "/&$type_name{}/d" "$signature_dir/export.go"
}

backup_export() {
	local signature_dir="$1"
	# Backup the export file
	cp "$signature_dir/export.go" "$SCRIPT_TMP_DIR/export.go.bak"
}

restore_export() {
	local signature_dir="$1"
	# Restore the export file from backup if it exists
	if [ -f "$SCRIPT_TMP_DIR/export.go.bak" ]; then
		cp "$SCRIPT_TMP_DIR/export.go.bak" "$signature_dir/export.go"
	else
		info "No backup export file found"
	fi
}