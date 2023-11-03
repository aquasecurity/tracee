# CLI Policy Usage

This section details how to use the flags in the Tracee CLI.

## Applying Tracee Polcies

A [policy file](../index.md) can be applied in the Tracee command using the `--policy` flag and providing a path to the location of the policy file.

```console
tracee --policy ./policy.yml
```

## Using multiple policies

To specify multiple policies, users can either specify the directory, which contains all of the policies that they would like to load into Tracee, or by specifying the policies one by one.

Through a directory:

```console
tracee --policy ./policy-directory
```

By specifying individual policies:

```console
tracee --policy ./policy-one.yaml --policy ./policy-two.yaml 
```