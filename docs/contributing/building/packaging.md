# Creating Tracee Linux packages

> These instructions are meant to describe how to build Linux distributions
> packages. If you would like to have a local build and execution environment,
> [read this](./environment.md) instead.

## Ubuntu

You may use `builder/Makefile.packaging` to generate Ubuntu deb packages. It
will use docker containers to generate appropriate packages, so you don't need
to install build dependencies in your OS.

!!! Ubuntu Note

    !!! Building Tip

        * Focal (LTS)

        ```console
        make -f builder/Makefile.packaging ubuntu-bin-focal
        ```

        * Jammy (LTS)

        ```console
        make -f builder/Makefile.packaging ubuntu-bin-jammy
        ```

    !!! Versioning

        The ubuntu `.deb` packages have the following versioning format:

        `tracee-{ebpf,rules}_version~ubuntuver~builddate-lastcommit_arch.deb`

        Examples:

        ```text
        # focal
        tracee_0.6.5-111~20.04~2201281302-3a6874a_amd64.deb

        ...
        ```

        This allows upgrades among future releases of tracee AND ubuntu. It also allows
        you to upgrade to "in between releases" versions if a fix is needed.

    !!! Location Attention

        The packages will be generated in `dist/` directory.

## Fedora

You may use `builder/Makefile.packaging` to generate Fedora rpm packages. It
will use docker containers to generate appropriate packages, so you don't need
to install build dependencies in your OS.

!!! Fedora Note

    !!! Building Tip

        * 36 (still maintained)

        ```console
        make -f builder/makefile.packaging fedora-bin-36
        ```

        * 37 (latest)

        ```console
        make -f builder/makefile.packaging fedora-bin-37
        ```

    !!! Versioning Note

        The fedora `.rpm` packages have the following versioning format:

          `tracee-{ebpf,rules}-version-f{34,35,36}.builddate.lastcommit.arch.rpm`

        Examples:

        ```text
        # f36
        tracee-0.6.5.163-f36.2202140514.ef35306d.x86_64.rpm

        # f37
        tracee-0.8.0.rc-f37.2207080417.07c8af7.x86_64.rpm
        ...
        ```

        This allows upgrades among future releases of tracee AND fedora. It also allows
        you to upgrade to "in between releases" versions if a fix is needed.

    !!! Location Attention

        The packages will be generated in `dist/` directory.
