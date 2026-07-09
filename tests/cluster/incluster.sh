#!/usr/bin/env bash
#
# incluster.sh - runs INSIDE the test VM. Stands up a single-node k3s cluster, builds/loads the local Tracee
# and operator images, deploys the Helm chart, applies a Policy CRD, and verifies Tracee runs and traces per
# the policy. Invoked by tests/cluster/run.sh (which brings the VM up first); can also be run standalone on
# any Linux host with docker + a real kernel.
#
# Knobs (env):
#   REPO_DIR       repo root (default: script's ../../ )
#   NAMESPACE      k8s namespace for tracee (default: tracee-system)
#   USE_RELEASED   1 = pull docker.io/aquasec/tracee instead of building locally (deploy-mechanics only)
#   SKIP_BUILD     1 = TRACEE_IMAGE is ALREADY built locally; just import it (no docker build). Used by the
#                  k8s-smoke CI, which pre-packages prebuilt binaries via builder/Dockerfile.ci.
#   TRACEE_IMAGE   image ref to deploy (default: tracee:cluster-test, or the released tag). One image serves
#                  BOTH the tracee DaemonSet and the operator Deployment (it carries both binaries).
#   POLICY_FILE    Policy CRD to apply (default: examples/policies/yaml/k8s/context_comm.yaml)
#   READY_TIMEOUT  seconds to wait for rollout / events (default: 180)
#   KEEP           1 = leave the cluster/deployment up after the run (for debugging)
#
set -euo pipefail

SCRIPT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
REPO_DIR=${REPO_DIR:-$(cd "${SCRIPT_DIR}/../.." && pwd)}
NAMESPACE=${NAMESPACE:-tracee-system}
USE_RELEASED=${USE_RELEASED:-0}
SKIP_BUILD=${SKIP_BUILD:-0}
POLICY_FILE=${POLICY_FILE:-examples/policies/yaml/k8s/context_comm.yaml}
READY_TIMEOUT=${READY_TIMEOUT:-180}
KEEP=${KEEP:-0}

if [ "${USE_RELEASED}" = "1" ]; then
    TRACEE_IMAGE=${TRACEE_IMAGE:-docker.io/aquasec/tracee:latest}
else
    TRACEE_IMAGE=${TRACEE_IMAGE:-tracee:cluster-test}
fi

log()  { printf '\n\033[1;34m>>> %s\033[0m\n' "$*"; }
ok()   { printf '\033[1;32m  ok: %s\033[0m\n' "$*"; }
die()  { printf '\033[1;31m  FAIL: %s\033[0m\n' "$*" >&2; exit 1; }
have() { command -v "$1" >/dev/null 2>&1; }

KUBECTL="k3s kubectl"
HELM="helm"

# ------------------------------------------------------------------------------------------------------------
# Phase 1: single-node k3s
# ------------------------------------------------------------------------------------------------------------
install_k3s() {
    log "Phase 1: k3s"
    if have k3s && systemctl is-active --quiet k3s; then
        ok "k3s already running"
    else
        # --disable traefik/servicelb: not needed; tracee runs as a DaemonSet with host access.
        curl -sfL https://get.k3s.io | INSTALL_K3S_EXEC="--disable traefik --disable servicelb" sh -
        systemctl is-active --quiet k3s || die "k3s failed to start"
        ok "k3s installed"
    fi
    export KUBECONFIG=/etc/rancher/k3s/k3s.yaml
    for _ in $(seq 1 "${READY_TIMEOUT}"); do
        ${KUBECTL} get nodes 2>/dev/null | grep -q ' Ready ' && break
        sleep 1
    done
    ${KUBECTL} get nodes | grep -q ' Ready ' || die "k3s node not Ready"
    ok "node Ready"
    have helm || { curl -fsSL https://raw.githubusercontent.com/helm/helm/main/scripts/get-helm-3 | bash; }
}

# ------------------------------------------------------------------------------------------------------------
# Phase 2: build + import images (or pull released)
# ------------------------------------------------------------------------------------------------------------
build_and_import_images() {
    log "Phase 2: image (${TRACEE_IMAGE})"
    cd "${REPO_DIR}"
    if [ "${USE_RELEASED}" = "1" ]; then
        # Pre-pull into k3s' containerd so IfNotPresent works without registry auth at pod start.
        k3s ctr images pull "${TRACEE_IMAGE}" || die "pull ${TRACEE_IMAGE}"
        ok "using released image ${TRACEE_IMAGE}"
    elif [ "${SKIP_BUILD}" = "1" ]; then
        # Image already built by the caller (e.g. the k8s-smoke workflow's COPY-only builder/Dockerfile.ci,
        # which packages prebuilt binaries instead of recompiling). Just import it into k3s' containerd.
        have docker || die "docker not found (needed to import the prebuilt image)"
        docker image inspect "${TRACEE_IMAGE}" >/dev/null 2>&1 || die "prebuilt image ${TRACEE_IMAGE} not found (SKIP_BUILD=1)"
        docker save "${TRACEE_IMAGE}" | k3s ctr images import - || die "import ${TRACEE_IMAGE}"
        ok "prebuilt image imported into k3s"
    else
        # Dockerfile.alpine-tracee-container produces ONE image carrying both the tracee and tracee-operator
        # binaries (see its COPY of dist/tracee + dist/tracee-operator), which is exactly what the Helm chart's
        # single .Values.image serves to both workloads. The build needs the toolchain present in the test VM
        # (docker + clang/llvm + libbpf). NOTE: adjust FLAVOR/BTFHUB on first run if your build needs it.
        have docker || die "docker not found (needed to build the local image)"
        log "building tracee image (contains tracee + tracee-operator)"
        docker build -f builder/Dockerfile.alpine-tracee-container \
            --build-arg FLAVOR=tracee-core --build-arg BTFHUB=0 \
            -t "${TRACEE_IMAGE}" . || die "tracee image build"
        # Import into k3s' containerd (k3s cannot see the docker daemon's images).
        docker save "${TRACEE_IMAGE}" | k3s ctr images import - || die "import ${TRACEE_IMAGE}"
        ok "image built + imported into k3s"
    fi
}

# ------------------------------------------------------------------------------------------------------------
# Phase 3: deploy the Helm chart
# ------------------------------------------------------------------------------------------------------------
deploy_chart() {
    log "Phase 3: helm install (ns=${NAMESPACE})"
    cd "${REPO_DIR}"
    local trepo="${TRACEE_IMAGE%:*}" ttag="${TRACEE_IMAGE##*:}"
    # operator.create=false: the operator's only job is to restart the DaemonSet on a Policy CRD change; this
    # test does that restart itself (apply_policy), so it doesn't need the operator (and Dockerfile.ci then
    # carries only the tracee binary). The Policy CRD ships in the chart's crds/ dir, installed regardless.
    KUBECONFIG=/etc/rancher/k3s/k3s.yaml ${HELM} upgrade --install tracee ./deploy/helm/tracee \
        --namespace "${NAMESPACE}" --create-namespace \
        --set image.repository="${trepo}" --set image.tag="${ttag}" --set image.pullPolicy=IfNotPresent \
        --set operator.create=false \
        --wait --timeout "${READY_TIMEOUT}s" || die "helm install (see: kubectl -n ${NAMESPACE} get pods)"
    ok "chart installed (operator disabled)"
}

# ------------------------------------------------------------------------------------------------------------
# Phase 4: apply a Policy CRD
# ------------------------------------------------------------------------------------------------------------
apply_policy() {
    log "Phase 4: apply policy ${POLICY_FILE}"
    export KUBECONFIG=/etc/rancher/k3s/k3s.yaml
    ${KUBECTL} get crd policies.tracee.aquasec.com >/dev/null 2>&1 || die "Policy CRD not established"
    ${KUBECTL} apply -f "${REPO_DIR}/${POLICY_FILE}" || die "apply policy"
    ok "policy applied"

    # Tracee reads Policy CRDs at boot; with no operator, trigger the reload ourselves (what the operator's
    # Reconcile does): a rolling restart so the pods re-read the CRDs.
    ${KUBECTL} -n "${NAMESPACE}" rollout restart ds -l app.kubernetes.io/name=tracee || die "rollout restart"
    ${KUBECTL} -n "${NAMESPACE}" rollout status ds -l app.kubernetes.io/name=tracee --timeout="${READY_TIMEOUT}s" \
        || die "tracee not ready after restart"
    ok "tracee restarted to load the policy"
}

# ------------------------------------------------------------------------------------------------------------
# Phase 5: verify Tracee is running and tracing per the policy
# ------------------------------------------------------------------------------------------------------------
verify() {
    log "Phase 5: verify"
    export KUBECONFIG=/etc/rancher/k3s/k3s.yaml

    ${KUBECTL} -n "${NAMESPACE}" rollout status ds -l app.kubernetes.io/name=tracee --timeout="${READY_TIMEOUT}s" \
        || die "tracee DaemonSet not ready"
    ok "tracee DaemonSet ready"

    # The context_comm policy traces openat by comm=ls. Trigger it, then look for the event in tracee's output.
    local pod
    pod=$(${KUBECTL} -n "${NAMESPACE}" get pods -l app.kubernetes.io/name=tracee -o jsonpath='{.items[0].metadata.name}')
    [ -n "${pod}" ] || die "no tracee pod found"

    # Drive activity the policy should catch (openat by 'ls') INSIDE the poll loop: tracee's stdout is
    # block-buffered, so a one-shot burst can sit unflushed for the whole poll - continuous activity keeps
    # events flowing so they reach `kubectl logs`. Match either output schema ("name" or legacy "eventName").
    log "scanning tracee output for policy events (pod ${pod})"
    local deadline=$(( $(date +%s) + READY_TIMEOUT ))
    while [ "$(date +%s)" -lt "${deadline}" ]; do
        for _ in $(seq 1 5); do ls / >/dev/null 2>&1; done
        if ${KUBECTL} -n "${NAMESPACE}" logs "${pod}" --tail=2000 2>/dev/null | grep -qiE '"(eventName|name)":\s*"openat"'; then
            ok "observed openat events in tracee output - policy is active"
            return 0
        fi
        sleep 2
    done
    ${KUBECTL} -n "${NAMESPACE}" logs "${pod}" --tail=40 || true
    die "no policy events observed within ${READY_TIMEOUT}s"
}

cleanup() {
    [ "${KEEP}" = "1" ] && { log "KEEP=1: leaving cluster + deployment up"; return; }
    log "cleanup"
    export KUBECONFIG=/etc/rancher/k3s/k3s.yaml
    ${KUBECTL} delete -f "${REPO_DIR}/${POLICY_FILE}" --ignore-not-found >/dev/null 2>&1 || true
    ${HELM} -n "${NAMESPACE}" uninstall tracee >/dev/null 2>&1 || true
    ok "removed deployment (k3s left installed; run 'k3s-uninstall.sh' to remove the cluster)"
}

main() {
    [ "$(id -u)" -eq 0 ] || die "run as root (k3s + image import need it)"
    install_k3s
    build_and_import_images
    deploy_chart
    apply_policy
    verify
    cleanup
    log "CLUSTER TEST PASSED"
}
main "$@"
