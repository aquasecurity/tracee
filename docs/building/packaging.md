# Creating Tracee Linux packages

> These instructions are meant to describe how to build Linux distributions
> packages If you would like to have a local building building and execution
> environment, [read this](./environment.md) instead.

## Ubuntu Linux

Tracee has a directory "packaging" with a skeleton of the needed "debian/"
directory called "ubuntu". This skeleton is used by "packaging/ubuntu-pkgs.sh"
script and this script should run from an Ubuntu Linux box.

It is not needed that you have an Ubuntu box to generate the Ubuntu `.deb`
packages. Instead, you may use the `builder/Makefile.packaging` make script to
build it for you (by using Docker images).

### Building

With this make script, you're able to build binary `.deb` packages for:

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

  `tracee-{ebpf,rules}_version~ubuntuver~buildate-lastcommit_arch.deb`

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

The packages will be generated in `dist/` directory, together with the built
binaries.
