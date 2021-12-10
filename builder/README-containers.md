## Instructions on how to use the 'tracee-make' docker container

> Here you will find an explanation about what
> [Makefile.docker](./Makefile.docker) does "under the hood".

### To create **tracee-make** container:

Create an alpine based docker container (musl based):

```
$ docker build -f Dockerfile.alpine-tracee-make \
    -t alpine-tracee-make:latest \
    --build-arg uid=$UID \
    --build-arg gid=$GID \
    .
```

OR create an ubuntu based docker container (glibc based):

```
$ docker build -f Dockerfile.ubuntu-tracee-make \
    -t ubuntu-tracee-make:latest \
    --build-arg uid=$UID \
    --build-arg gid=$GID \
    .
```

> You may generate static (STATIC=1) or dynamic (STATIC=0) binaries. Be aware
> that, if not static, your binaries will depend on either `musl` or `glibc`,
> based on the distro you picked as the builder distro.

> If you chose to build your binaries with STATIC=1, then you'll have something
> close to an **universal** binary, able to run in different distros.

### To exec the 'tracee-make' shell:

Use your newly-generated build environment:

```
$ docker run --rm --pid=host --privileged \
    -v $(pwd):/tracee \
    --entrypoint=/bin/bash \
    -it xxxx-tracee-make
```

```
tracee@b7c4c3ea733e[/tracee]$ make -f Makefile.one clean
tracee@b7c4c3ea733e[/tracee]$ make -f Makefile.one all
tracee@b7c4c3ea733e[/tracee]$ sudo ./dist/tracee-ebpf --debug --trace 'event!=sched*'
```

> Where xxxx is the distro you've picked as builder distro ('alpine' or
> 'ubuntu').

You may also mount your host kernel headers to build non-CORE tracee-ebpf:

```
$ docker run --rm --pid=host --privileged \
    -v $(pwd):/tracee \
    -v /lib/modules:/lib/modules:ro \
    -v /usr/src:/usr/src:ro \
    -v /tmp/tracee:/tmp/tracee \
    -it xxxx-tracee-make /bin/bash
```

### To use 'tracee-make' as replacement for the make tool:

```
$ docker run --rm --pid=host --privileged \
    -v $(pwd):/tracee \
    -v /lib/modules:/lib/modules:ro \
    -v /usr/src:/usr/src:ro \
    -v /tmp/tracee:/tmp/tracee \
    -it xxxx-tracee-make \
    make -f Makefile.one [clean|core|all|test|...]
```

> Where xxxx is the distro you've picked as builder distro ('alpine' or
> 'ubuntu').
