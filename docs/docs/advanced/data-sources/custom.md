# Custom data sources

Custom data sources are currently supported through the plugin mechanism.

!!! Attention
    Eventually you will find out that Golang Plugins aren't very useful if
    you consider all the problems that emerge from using it:

    1. **Can't use different go versions** (need to compile the go plugin
        with the exact same version that was used to build Tracee).

    2. Both Tracee and your golang plugin data source must be built with the
        **exact same GOPATH** or you will get a "plugin was built with a
        different version of package XXX" error.

    3. Any **dependency** you have in your plugin should be of the **same
        version** with the dependencies of Tracee.

    4. Compiling tracee statically is sometimes useful to have a **complete
        portable eBPF tracing/detection solution**. One good example when
        statically compiling tracee is a good idea is to have a single
        binary capable of running in GLIBC (most of them) and MUSL (Alpine)
        powered Linux distros.

    At the end, creating a golang data source plugin won't have the practical
    effects as a plugin mechanism should have, so it is preferred to have
    built-in data source (re)distributed with newer binaries (when you
    need to add/remove data sources from your environment) **FOR NOW**.

There are two main reasons to write your own data source:

1. To provide a stable "tracee-native" querying API for some externally owned data you need in a signature (for example some DB access)
1. To provide an externally writable and internally readable data source in a data source (for example configuration)

An example for an implementation of the latter is given [here](./write.md).

# Integrating into a plugin

Since Data Sources should usually be supplied alongside a relevant data source, providing them is as easy
as using another symbol in the plugin.

Simply add the following symbol in your plugin entrypoint:
```golang
    var ExportedDataSources = []detect.DataSource{
        ...
        mydatasource.New(someDependency),
    }
```

And the data source will be available in data sources through the specified namespace and id given
in your code.
