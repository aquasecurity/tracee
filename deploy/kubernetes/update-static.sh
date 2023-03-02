#!/usr/bin/env bash

kubectl kustomize -o tracee/tracee.yaml ./kustomize/base
kubectl kustomize -o tracee-postee/tracee.yaml ./kustomize/postee
