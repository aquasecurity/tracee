# Configuring Tracee with CLI

The `--config` flag allows you to specify global configuration options for Tracee by providing a configuration file in YAML or JSON format, among other supported formats. The `--config` flag can be used to set any flag that is available through the command line interface (CLI), except for a few reserved flags.

## Usage

To use the `--config` flag, you need to provide the path to the configuration file. For example, if you have a YAML configuration file located at /path/to/tracee-config.yaml, you can load it with the following command:

```console
tracee --config /path/to/tracee-config.yaml
```
