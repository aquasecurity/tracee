# Config

## Configuring Tracee with the `--config` Flag

The `--config` flag allows you to specify global configuration options for Tracee by providing a configuration file in YAML or JSON format, among other supported formats. The `--config` flag can be used to set any flag that is available through the command line interface (CLI), except for a few reserved flags.

## Usage

To use the `--config` flag, you need to provide the path to the configuration file. For example, if you have a YAML configuration file located at /path/to/tracee-config.yaml, you can load it with the following command:

```console
tracee --config /path/to/tracee-config.yaml
```

You can also override specific configuration options by passing additional flags on the command line. For example, the following command overrides the log level set in the configuration file with info:

```console
sudo ./dist/tracee --config ./examples/config/global_config.yaml --log info
```

!!! Note
    Any flags specified on the command line will take precedence over the values specified in the configuration file.

## Configuration File Format

The configuration file can be in any format supported by the [viper](https://github.com/spf13/viper) library, which includes YAML, JSON, TOML, INI, HCL and Java properties. The configuration file should contain a mapping of flag names to their values. For example, to output aggregated debug level logs every default seconds `--log debug --log aggregate`, you would add the following to your configuration file:

```yaml
log:
    - debug
    - aggregate
```

## Reserved Flags

There are a few flags that are reserved for the CLI and cannot be set through the configuration file. These include:

- `--config`: This flag is used to specify the configuration file, so it cannot be set through the configuration file itself.
- `--capture`: This flag is used to specify which events should be captured by Tracee, so it cannot be set through the configuration file.
- `--policy`: This flag is used to specify a policy file for Tracee, so it cannot be set through the configuration file.
- `--filter `: This flag is used to specify an event filter for Tracee via CLI and via policy file loading mechanism (the --policy flag), so it cannot be set through the configuration file.

## Example Configuration Files

To help you get started with configuring Tracee using the `--config` flag, we've provided two example configuration files in the `examples/config` directory of the Tracee repository:

- `examples/config/global_config.json`: This file contains an example configuration in JSON format.
- `examples/config/global_config.yaml`: This file contains the same example configuration as global_config.json, but in YAML format.

These example files demonstrate how you can set various configuration options using the `--config` flag. You can use these files as a starting point for your own configuration, or as a reference for the available configuration options.

To use one of the example configuration files with Tracee, simply pass the path to the file as an argument to the -`-config` flag. For example, to use the YAML configuration file, you could run the following command:

```console
tracee --config examples/config/global_config.yaml
```

By starting with one of these example files and modifying it to suit your needs, you can quickly get up and running with Tracee's configuration options.