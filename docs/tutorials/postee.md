# Setting up Tracee with Postee

In this tutorial we will showcase how you can set up Tracee with Postee. Whenever malicious behaviour is detected, Postee will send a notification to Slack.

## Overview Postee

[Postee](https://github.com/aquasecurity/postee) is a simple message routing application that receives input messages through a webhook interface, and can take enforce actions using predefined outputs via integrations.

## Prerequisite

This tutorial is based on Kubernetes, to follow along, please make sure you have access to the following:

A Kubernetes cluster & kubectl connected -- the cluster must have access to a storage class. If you are on an Intel-based machine, you could use the following local clusters:
- microk8s with `hostpath-storage` [addone enabled](https://microk8s.io/docs/addons)
- minikube with [PersistentVolume](https://minikube.sigs.k8s.io/docs/handbook/persistent_volumes/)
Note that we have not tested this yet.

In this tutorials, we will be using a 1-node DigitalOcean Kubernetes cluster.

Additionally, you will need to have [Helm](https://helm.sh/docs/intro/install/) installed locally.

## Installation

We are going to install Tracee with Postee enabled through the [Tracee Helm Chart.]() More details can be found in the part of the [installation documentation](https://aquasecurity.github.io/tracee/dev/getting-started/installing/kubernetes/)

First, we will add the Aqua Helm repository to our Helm repository list:
```
helm repo add aqua https://aquasecurity.github.io/helm-charts/
helm repo update
```

Next, we can install the Helm Chart inside of our cluster with the following command:
```
helm install tracee aqua/tracee \
        --namespace tracee-system --create-namespace \
        --set hostPID=true \
        --set postee.enabled=true
```

Next, make sure that the resources in the `tracee-system` namespace are running correctly with the following command:
```
kubectl get all -n tracee-system
```

## Configure Postee

There are two ways to configure Postee to send alerts to your various communication channels:
- Through the PosteeUI
- Through

### Configuring Postee through the PosteeUI

Port-forward the PosteeUI service to your localhost with the following command:
```
kubectl port-forward service/tracee-posteeui -n tracee-system 8000:8000
```

This will now allow you to access Postee in the UI at http://localhost:8000/login

The username is: admin
The password is: admin

When you first login, you will be presented with a tour of the UI -- we can create our first route as follows:

![Define Postee route in the UI](../images/postee-routes.png)

- Select all options for the event
- Select Slack to receive messages to 

Next, we have to configure Slack in the Action section of the UI:

![Set up Slack Webhook](../images/postee-action-slack.png)

To do so, you will need the webhook URL for the Slack channel that you would like to connect. [The Slack documentation](https://api.slack.com/messaging/webhooks#enable_webhooks) details how you can set up the Webhook for a channel in one of your Slack workspaces.

Alternatively, you can set up and configure any other of the available actions.

Note that while you set up the action, you can already try the configuration through the PosteeUI; look for the `Test config` button in the top right of the Slack action. This will then send a test message through the webhook to your chosen Slack channel.

### Configuring Postee through the ConfigMap

Alternatively, it is possible to confifure Postee through the ConfigMap in Kubernetes.

To do so, we first have to edit the ConfigMap with the routes and actions that we want Postee to take:
```
name: tenant            #  The tenant name
aqua-server:            #  URL of Aqua Server for links. E.g. https://myserver.aquasec.com
max-db-size: 1000MB       #  Max size of DB. <numbers><unit suffix> pattern is used, such as "300MB" or "1GB". If empty or 0 then unlimited
db-verify-interval: 1   #  How often to check the DB size. By default, Postee checks every 1 hour

# Routes are used to define how to handle an incoming message
routes:
- name: actions-route
  input: contains(input.SigMetadata.ID, "TRC")
  outputs: [my-slack]
  template: raw-json

# Templates are used to format a message
templates:
- name: raw-json
  rego-package: postee.rawmessage.json

# Rules are predefined rego policies that can be used to trigger routes
rules:
- name: Initial Access
- name: Credential Access
- name: Privilege Escalation
- name: Defense Evasion
- name: Persistence

# Actions are target services that should consume the messages
actions:
- name: my-slack
  type: slack
  enable: true
  url: 
```


## Triggering the Slack action in Postee through Tracee detection

Now that we have configured Postee correctly, we need to make sure that Postee will be triggered when there are new detections in Tracee.

To do so, we will first install an nginx container inside our cluster, then enter the container and execute `strace`. These are the commands used:
```
kubectl create deployment nginx --image=nginx  # creates a deployment

kubectl exec -ti deployment/nginx -- bash  # get a bash into it

$~ apt update && apt install -y strace
$~ strace ls
```

Once done, you should see the detection in the Tracee logs:
```
kubectl logs tracee-vw889 -n tracee-system
```

Note: You will have to change the tracee pod name in the command above with the name of the tracee pod inside your cluster.


