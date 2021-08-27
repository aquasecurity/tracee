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
rm -f pipe && mkfifo pipe && exec <>pipe

tracee_ebpf_readiness=/tmp/tracee/out/tracee.pid
# start tracee-ebpf in the background
rm -f $tracee_ebpf_readiness
echo "starting tracee-ebpf..."
($TRACEE_EBPF_EXE --output=format:gob --security-alerts >pipe; kill $$)&
tracee_ebpf_pid=$!

# wait for tracee-ebpf to: load / exit / timeout
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
$TRACEE_RULES_EXE --input-tracee=file:stdin --input-tracee=format:gob $@ <pipe
