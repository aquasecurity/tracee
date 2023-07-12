# Cosign: verify tracee signature


## Prerequisites

Before you begin, ensure that you have the following:

- [cosign](https://docs.sigstore.dev/cosign/installation/)

## Verify tracee signature

Tracee images are signed with cosign keyless. To verify the signature we can run the command:

```console
cosign verify aquasec/tracee:{{ git.tag }}  --certificate-oidc-issuer https://token.actions.githubusercontent.com --certificate-identity-regexp https://github.com/aquasecurity/tracee | jq
```
