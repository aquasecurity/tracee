# Cosign: verify tracee signature


## Prerequisites

Before you begin, ensure that you have the following installed:

- [cosign](https://docs.sigstore.dev/cosign/installation/)

## Verify tracee signature

Tracee images are signed with cosign keyless. To verify the signature we can run the command:

```console
cosign verify aquasec/tracee:tag-name  --certificate-oidc-issuer https://token.actions.githubusercontent.com --certificate-identity-regexp https://github.com/aquasecurity/tracee | jq
```

Note that all of the tag-names can be found on the [Tracee Docker Hub Registry](https://hub.docker.com/r/aquasec/tracee/tags).

The output should look similar to the following:
![Tracee Signature Scanning](../images/signatures.png)
