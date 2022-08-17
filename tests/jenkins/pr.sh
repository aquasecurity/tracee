#!/bin/bash

#
# This script should be executed by jenkins on PRs
#

set -o xtrace

declare -a MakeTargets=("all" "check-fmt" "check-vet" "check-staticcheck" "test-unit" "test-integration" "rules" "test-rules")

for target in "${MakeTargets[@]}"; do
	make $target
done

DONTSLEEP=0 ISNONCORE=0 ./tests/kerneltest.sh
