# Kubernetes Considerations for Tracee Contributors

1. **Set up a Local Kubernetes Cluster**

    We recommend using a local Kubernetes cluster for development and testing. Popular options include:

    * **kind:** Kubernetes IN Docker
    * **minikube:** Runs a single-node cluster in a VM
    * **MicroK8s:** Lightweight, snap-based Kubernetes

    Tracee's Makefile provides convenient targets for setting up MicroK8s:

    ```bash
    make -f builder/Makefile.k8s help
    ```

    ```text
    To build the operator docker container:

        $ make -f builder/Makefile.k8s build

    To generate the kubernetes manifests:

        $ make -f builder/Makefile.k8s manifests

    To generate operator code:

        $ make -f builder/Makefile.k8s generate

    Or simply:

        $ make -f builder/Makefile.k8s
    ```

2. **Deploy Tracee**

    Deploy Tracee to your chosen local cluster. The deployment method will vary depending on your needs:

    * **DaemonSet:** For system-wide tracing, deploy Tracee as a DaemonSet.
    * **Tracee Operator:**  Use the Tracee operator for simplified management.
    * **Other Methods:** Explore alternative methods like sidecar containers based on your use case.

3. **Test Your Changes**

    Test your modifications with realistic scenarios within the Kubernetes environment.  Consider these examples:

    * **Application Monitoring:** Deploy sample applications and observe Tracee's event capture for expected behavior.
    * **Network Policies:**  Configure network policies to restrict pod communication and verify Tracee captures relevant network events.
    * **Resource Constraints:**  Apply resource limits to pods and ensure Tracee functions correctly under constrained conditions.
    * **Security Policies:**  Implement Pod Security Policies and/or Security Contexts to validate Tracee's compliance and event capture in secure environments.

4. **Monitor Tracee's Performance**

    Utilize Kubernetes' observability tools to monitor Tracee:

    * **Resource Usage:** Track pod resource consumption (CPU, memory) using `kubectl top` or monitoring dashboards.
    * **Logs:** Analyze Tracee logs for errors, warnings, or unexpected behavior using `kubectl logs`.
    * **Kubernetes Metrics:**  If available, leverage Kubernetes metrics to gain insights into Tracee's performance.

5. **Clean Up**

    After testing, remove deployed Tracee components and test resources to maintain a clean cluster environment.

## Kubernetes-Specific Features

If your contribution involves Kubernetes-specific features within Tracee (e.g., capturing Kubernetes events or metadata), ensure you test these functionalities thoroughly within the cluster environment. Pay close attention to event accuracy and any integration with Kubernetes APIs.
