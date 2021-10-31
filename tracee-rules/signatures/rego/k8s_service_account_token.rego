package tracee.TRC_8

import data.tracee.helpers

__rego_metadoc__ := {
    "id": "TRC-8",
    "version": "0.1.0",
    "name": "K8S Service Account Token Use Detected",
    "description": "The Kubernetes service account token file was read on your container. This token is used to communicate with the K8S API server, Adversaries may try and communicate with the API server to gather information/credentials, or even run more containers and laterally expand their grip on your systems.",
    "tags": ["container"],
    "properties": {
        "Severity": 0,
        "MITRE ATT&CK": "Credential Access: Credentials from Password Stores"
    }
}

eventSelectors := [
    {
       "source": "tracee",
       "name": "security_file_open",
       "origin": "container"
    }
]

tracee_selected_events[eventSelector] {
	eventSelector := eventSelectors[_]
}

tracee_match {

    input.eventName == "security_file_open"

    flags = helpers.get_tracee_argument("flags")
    helpers.is_file_read(flags)

    pathname := helpers.get_tracee_argument("pathname")
    contains(pathname,"secrets/kubernetes.io/serviceaccount")
    endswith(pathname,"token")

    process_names_allowlist := {"flanneld", "kube-proxy", "etcd", "kube-apiserver", "coredns", "kube-controller"}
    not process_names_allowlist[input.processName]
}
