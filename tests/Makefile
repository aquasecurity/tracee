clean:
	rm -f runner

build-runner:
	go build -o runner runner.go

build-trainer-docker:
	docker build -t tracee-trainer:latest .

build-tracee-docker:
	cd .. && make -f builder/Makefile.tracee-container build-alpine-tracee-core

run-tests: clean build-runner build-trainer-docker build-tracee-docker
	go test -v -run=TestTraceeSignatures