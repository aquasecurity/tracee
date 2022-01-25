clean:
	rm -f runner

build-runner:
	go build -o runner runner.go

build-trainer-docker:
	docker build -t tracee-trainer:latest .

build-tracee-docker-core:
	cd .. && make -f builder/Makefile.tracee-container build-alpine-tracee-core

build-tracee-docker-nocore:
	cd .. && make -f builder/Makefile.tracee-container build-alpine-tracee-nocore

build-tracee-docker-core-btfhub:
	cd .. && make -f builder/Makefile.tracee-container build-alpine-tracee-core-btfhub

run-tests: clean build-runner build-trainer-docker build-tracee-docker-core build-tracee-docker-nocore build-tracee-docker-core-btfhub
	go test -v -run=TestTraceeSignatures