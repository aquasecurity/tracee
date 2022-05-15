# tracee-distro-tester

Tracee Distro Tester is meant to test Tracee eBPF CO-RE features in multiple
enviroments and kernels. It works by creating a docker container that receives
arguments such as the type of acceleration to use (kvm or tcg) and the test
name to execute. This container creates a VM (fully emulated or kvm assisted),
runs tracee on that VM and starts a docker container, inside created VM, that
will simulate the security issue for the requested test.

> It might also be used as a standalone tool while developing tracee.

## How to use Tracee Distro Tester

1. First pull the container image you would like to use:

- centos8: CentOS Stream8 (kernel 4.18) (RHEL 8)
- centos9: CentOS Stream9 (kernel 5.14) (RHEL 9)
- fedora34: Fedora 34 (kernel 5.11)
- fedora35: Fedora 35 (kernel 5.14)
- fedora36: Fedora 36 (kernel 5.17)
- focal: Ubuntu Focal (kernel 5.4)
- focalhwe: Ubuntu Focal HWE (kernel 5.13)
- jammy: Ubuntu Jammy (kernel 5.15)

```
$ docker image pull rafaeldtinoco/tracee-distro-tester:<distro>
```

Then run the image like the following examples:

```
docker run --rm --privileged -v $(pwd):/tracee:rw -e kvm_accel=kvm -e test_name=TRC-2 -e non_core=0 -it rafaeldtinoco/tracee-distro-tester:centos8
docker run --rm --privileged -v $(pwd):/tracee:rw -e kvm_accel=tcg -e test_name=TRC-4 -e non_core=0 -it rafaeldtinoco/tracee-distro-tester:fedora34
docker run --rm --privileged -v $(pwd):/tracee:rw -e kvm_accel=kvm -e test_name=TRC-4 -e non_core=1 -it rafaeldtinoco/tracee-distro-tester:focal
```

2. Provide the correct bind mounts AND environment variables:

- `-v $(pwd):/tracee:rw` (if you're currently in tracee source directory)
- `-e kvm_accel=kvm` (or tcg if your environment doesn't support kvm)
- `-e test_name=TRC-7` (pick one test from the "list-tests" command, requires "(1)")
- `-e non_core=1` (if you want to use non CO-RE eBPF object)

> Make sure you execute a `make clean` before running different docker images,
> as the binaries will be built for the previous one and should be cleaned
> due to userland dependencies. Because the images run as root, you can clean
> your tree with a simple `sudo make clean`.

3. Check return code

The return code from the docker run will tell you if the test has succeeded or
failed (0 or 1). Test will only succeed if there was the correct detection
for the selected test. If there were compilation errors, or virtual machine
issues, or anything else, there is a 30 second timeout in place to fail after
the test execution attempt.
