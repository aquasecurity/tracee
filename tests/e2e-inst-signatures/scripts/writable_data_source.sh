#!/bin/bash

exit_err() {
    echo -n "ERROR: "
    echo $@
    exit 1
}

# build the tester
go build -o ./tests/e2e-inst-signatures/scripts/ds_writer/ds_writer tests/e2e-inst-signatures/scripts/ds_writer/*.go

# run the ds_writer 4 times in parallel
# each instance pollutes with a stream of a 1000 key values, then writes the given input
# the signature searches for this final input
./tests/e2e-inst-signatures/scripts/ds_writer/ds_writer -key "bruh" -value "moment" &
./tests/e2e-inst-signatures/scripts/ds_writer/ds_writer -key "bruh" -value "moment" &
./tests/e2e-inst-signatures/scripts/ds_writer/ds_writer -key "bruh" -value "moment" &
./tests/e2e-inst-signatures/scripts/ds_writer/ds_writer -key "bruh" -value "moment"
