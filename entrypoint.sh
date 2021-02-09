#!/bin/sh

TRACEE_EBPF_EXE=${TRACEE_EBPF_EXE:="/tracee/tracee-ebpf"}
TRACEE_MOUNT_EXE=${TRACEE_MOUNT_EXE:="mount"}
TRACEE_WEBHOOK_CONFIG=${TRACEE_WEBHOOK_CONFIG:="/tmp/tracee/integrations-config.yaml"}
TRACEE_WEBHOOK_EXE=${TRACEE_WEBHOOK_EXE:="/tracee/falcosidekick"}
TRACEE_RULES_EXE=${TRACEE_RULES_EXE:="/tracee/tracee-rules"}

$TRACEE_MOUNT_EXE | grep -q 'debugfs on /sys/kernel/debug'
if ! $TRACEE_MOUNT_EXE | grep -q 'debugfs on /sys/kernel/debug'; then
  $TRACEE_MOUNT_EXE -t debugfs debugfs /sys/kernel/debug/
fi

if [ "$1" = "trace" ]; then
	shift
	$TRACEE_EBPF_EXE $@
	exit
fi

if [ "$1" = "--list" ]; then
	shift
	$TRACEE_RULES_EXE --list
	exit
fi

if [ "$1" = "--rules" ]; then
	flag_rules="$1=$2"
fi

if [ -f $TRACEE_WEBHOOK_CONFIG ]; then
	flag_webhook_config="--config-file=$TRACEE_WEBHOOK_CONFIG"
fi

if $TRACEE_WEBHOOK_EXE $flag_webhook_config& then
	flag_webhook_url="--webhook=http://localhost:2801"
fi

$TRACEE_EBPF_EXE --output=format:gob | $TRACEE_RULES_EXE --input-tracee=file:stdin --input-tracee=format:gob $flag_webhook_url $flag_rules
