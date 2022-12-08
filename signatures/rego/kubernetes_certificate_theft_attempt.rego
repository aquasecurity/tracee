package tracee.TRC_10

import data.tracee.helpers

__rego_metadoc__ := {
	"id": "TRC-10",
	"version": "0.1.0",
	"name": "K8S TLS Certificate Theft Detected",
	"eventName": "k8s_cert_theft",
	"description": "Kubernetes TLS certificate theft was detected. TLS certificates are used to establish trust between systems, the kubernetes certificate is used to to enable secured communication between kubernetes components, like the kubelet, scheduler, controller and API server. An adversary may steal a kubernetes certificate on a compromised system to impersonate kuberentes components within the cluster.",
	"tags": ["linux", "container"],
	"properties": {
		"Severity": 3,
		"MITRE ATT&CK": "Credential Access: Steal Application Access Token",
	},
}

eventSelectors := [{
	"source": "tracee",
	"name": "security_file_open",
	"origin": "*",
}]

tracee_selected_events[eventSelector] {
	eventSelector := eventSelectors[_]
}

tracee_match {
	input.eventName == "security_file_open"

	flags = helpers.get_tracee_argument("flags")
	helpers.is_file_read(flags)

	pathname = helpers.get_tracee_argument("pathname")
	startswith(pathname, "/etc/kubernetes/pki/")

	process_names_blocklist := {"kube-apiserver", "kubelet", "kube-controller", "etcd"}
	not process_names_blocklist[input.processName]
}
