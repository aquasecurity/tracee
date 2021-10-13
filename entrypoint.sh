#!/bin/sh

TRACEE_EBPF_EXE=${TRACEE_EBPF_EXE:="/tracee/tracee-ebpf"}
TRACEE_RULES_EXE=${TRACEE_RULES_EXE:="/tracee/tracee-rules"}

# handle sub commands
if [ "$1" = "trace" ]; then
	shift
	exec $TRACEE_EBPF_EXE $@
	exit "$?"
fi

# override existing flags from tracee-rules
for arg in "$@"; do
	case arg in
		--list)
			$TRACEE_RULES_EXE --list
			exit "$?"
			;;
		--help)
			echo "Tracee - Runtime Security using eBPF"
			echo "For help, see https://github.com/aquasecurity/tracee"
			exit
			;;
	esac
done

# start, and pass all remaining flags to tracee-rules
EVENTS=$($TRACEE_RULES_EXE --list-events)
$TRACEE_EBPF_EXE --output=format:gob --security-alerts --trace event=$EVENTS | $TRACEE_RULES_EXE --input-tracee=file:stdin --input-tracee=format:gob $@
