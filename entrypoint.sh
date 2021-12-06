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

# create named pipe for communicating between tracee-ebpf and tracee-rules
tracee_pipe=/tmp/tracee/pipe
rm -f $tracee_pipe && mkfifo $tracee_pipe

# start tracee-ebpf in the background
EVENTS=$($TRACEE_RULES_EXE --list-events)
echo "starting tracee-ebpf..."
$TRACEE_EBPF_EXE --output=format:gob --output=option:parse-arguments --trace event=$EVENTS --output=out-file:$tracee_pipe &
tracee_ebpf_pid=$!

# wait for tracee-ebpf to: load / exit / timeout
tracee_ebpf_readiness=/tmp/tracee/out/tracee.pid
rm -f $tracee_ebpf_readiness
timeout=15
i=0
while [ ! -f $tracee_ebpf_readiness ] && $(ls /proc/$tracee_ebpf_pid >/dev/null 2>&1) && [ $i -le $timeout ]
do
	i=$(( i + 1 ))
	sleep 1
done

[ ! -f $tracee_ebpf_readiness ] && exit

# start tracee-rules
echo "starting tracee-rules..."
$TRACEE_RULES_EXE --input-tracee=file:$tracee_pipe --input-tracee=format:gob $@
