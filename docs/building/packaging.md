# Creating Tracee Linux packages

> These instructions are meant to describe how to build Linux distributions
> packages If you would like to have a local building building and execution
> environment, [read this](./environment.md) instead.

1. [Ubuntu](#Ubuntu-Linux)
2. [Fedora](#Fedora-Linux)

## Ubuntu Linux

You may use `builder/Makefile.packaging` to generate Ubuntu deb packages. It
will use docker containers to generate appropriate packages, so you don't need
to install build depencies in your OS.

### Building

*  Bionic (LTS)

  ```
  $ make -f builder/Makefile.packaging ubuntu-bin-bionic
  ```

*  Focal (LTS)

  ```
  $ make -f builder/Makefile.packaging ubuntu-bin-focal
  ```

*  Impish (Current)

  ```
  $ make -f builder/Makefile.packaging ubuntu-bin-impish
  ```

* Jammy (Devel)

  ```
  $ make -f builder/Makefile.packaging ubuntu-bin-jammy
  ```

### Versioning

The ubuntu `.deb` packages have the following versioning format:

  `tracee-{ebpf,rules}_version~ubuntuver~builddate-lastcommit_arch.deb`

Examples:

  ```
  # bionic
  tracee-ebpf_0.6.5-111~18.04~2201281255-3a6874a_amd64.deb
  tracee-rules_0.6.5-111~18.04~2201281255-3a6874a_amd64.deb

  # focal
  tracee-ebpf_0.6.5-111~20.04~2201281302-3a6874a_amd64.deb
  tracee-rules_0.6.5-111~20.04~2201281302-3a6874a_amd64.deb

  # impish
  tracee-ebpf_0.6.5-111~21.10~2201281314-3a6874a_amd64.deb
  tracee-rules_0.6.5-111~21.10~2201281314-3a6874a_amd64.deb
  ```

This allows upgrades among future releases of tracee AND ubuntu. It also allows
you to upgrade to "in between releases" versions if a fix is needed.

### Location

The packages will be generated in `dist/` directory.

## Fedora Linux

You may use `builder/Makefile.packaging` to generate Fedora rpm packages. It
will use docker containers to generate appropriate packages, so you don't need
to install build depencies in your OS.

### Building

* 34 (still maintained)

    ```
    make -f builder/Makefile.packaging fedora-bin-34
    ```

* 35 (latest)

    ```
    make -f builder/Makefile.packaging fedora-bin-35
    ```

* 36 (devel)

    ```
    make -f builder/Makefile.packaging fedora-bin-36
    ```

### Versioning

The fedora `.rpm` packages have the following versioning format:

  `tracee-{ebpf,rules}-version-f{34,35,36}.builddate.lastcommit.arch.rpm`

Examples:

  ```
  # f34
  tracee-ebpf-0.6.5.163-f34.2202140510.ef35306d.x86_64.rpm
  tracee-rules-0.6.5.163-f34.2202140510.ef35306d.x86_64.rpm

  # f35
  tracee-ebpf-0.6.5.163-f35.2202140512.ef35306d.x86_64.rpm
  tracee-rules-0.6.5.163-f35.2202140512.ef35306d.x86_64.rpm

  # f36
  tracee-ebpf-0.6.5.163-f36.2202140514.ef35306d.x86_64.rpm
  tracee-rules-0.6.5.163-f36.2202140514.ef35306d.x86_64.rpm
  ```

This allows upgrades among future releases of tracee AND fedora. It also allows
you to upgrade to "in between releases" versions if a fix is needed.

### Location

The packages will be generated in `dist/` directory.
