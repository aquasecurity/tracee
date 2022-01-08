clean:
	rm -f runner

build-runner:
	go build -o runner runner.go

build-trainer-docker:
	docker build -t tracee-trainer:latest .

build-tracee-docker:
	cd .. && make docker

run-tests: clean build-runner build-trainer-docker build-tracee-docker
	go test -v -run=TestTraceeSignatures