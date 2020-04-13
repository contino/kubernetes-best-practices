
# Container and Kubernetes Best Practices 


Table of Contents

Container Best Practices
Container Security and Images
Cluster Setup
Securing the Cluster
Cluster Operations
Application and Cluster Monitoring and Alerting
Cluster Authentication
Cluster Authorization
Troubleshooting Cluster
Troubleshooting Application

## Container Best Practices

Single process per container – This keeps image footprint to a minimum and is aligned with the adoption of microservices.

Image Tagging – Implement semantic versioning for application versions and git release or git hashes and then use Docker
 tags to tag the images with the git commit sha or tags for releases, as well as stable and previous. This allows for 
 fast rollback and identification of the application code running in the container. Avoid using the :latest tag when 
 deploying containers in production as it is harder to troubleshoot and debug issues
 Avoid running applications under root. Leverage RO where feasible. Ensure `USER` feature is used during docker image 
 build to downgrade the privileges.

Leverage Docker build cache – Handle application dependencies before copying application artifacts:	

Busting Cache only upon dependency changes
FROM node:latest
RUN npm install
COPY ./ /opt
RUN npm start

Dependency install will always be busted 
```yaml
FROM node:latest
COPY ./ /opt
RUN npm install \
npm start
```

Chain RUN command arguments to avoid too many layers being created (there’s a hard limit with aufs):

  RUN apt-get update && apt-get install -y \
  bzr \
  cvs \
  git \
  mercurial \
  subversion) 

Logging – Applications should log to stdout/stderr. Best practice is for logs to be logged to standard out/error and the logging sidecar or host agent to aggregate the logs. 

Config – Use environment variables to define runtime parameters, as opposed to hard config files. This separation of configuration and application code allows the container image to be immutable.

Secrets – Application secrets should be instantiated at run-time.

Container Security and Images

Embedded Malware – Continuously monitor images for embedded malware, including malware signature sets and behavioral detection heuristics method.

Embedded Clear Text Secrets – Securely store secrets outside the image and deliver them only to authorized containers at runtime. Enforce that secrets at rest and in transit are encrypted.

Use of Untrusted Images – Maintain a set of trusted images and registries by:

Continuously scanning for vulnerabilities and misconfigurations
Permitting  run time for authorized image within your cluster(s)
Whitelisting  approved container registries for your cluster use. Maintaining and validating image hash to ensure only authorized images are running. Use image signing with admission webhooks where appropriate
 
Insecure Connections to Registries – Ensure all connection channels to registries are encrypted and all data pushed to and pulled from a registry occurs between trusted endpoints and is encrypted in transit.

Stale images in registries – Ensure only up-to-date, authorized images are used based on a clear naming convention.

Insufficient authentication and authorization restrictions – Control and manage user access to registries via integration with directory services such as IAM/SSO. Audit and log access to registries (write access and read of sensitive data). Integrates automated scan into CI processes to ensure only authorized images can be used.

Unbounded Administrative Access – Orchestrators should use a least privilege access model to enable controlled and limited user access to sensitive resources (host, containers, images).

Dedicated service accounts for your application run-time - ensure kubernetes deployed application runtime relies on a dedicated service-account for such purpose. Avoid using default service accounts to promote access segregation. Use RBAC grouping as appropriate

Use dedicated namespace or namespace grouping for application runtime within kubernetes, to enforce access segregation. This option will enable namespace based isolation for firewall security rule creation, and also simplifies namespace-based forensic log collection.Unauthorized Access – Use strong authentication methods (e.g.: SSO) to secure access to cluster-wide admin accounts.

In addition, encrypt data at rest and control access to the data from containers only, regardless of the node they’re running on.
 
Poorly separated inter container network traffic – Configure orchestrators to segment network traffic into discrete virtual networks by sensitivity level (e.g.: public-facing apps can share a virtual network vs. internal apps).

Mixing of Workload Sensitivity Levels – Configure orchestrators to separate container and hosting zones by automatically grouping and deploying workloads to hosts based on their sensitivity level, purpose and threat posture. Further, for an additional layer of security, it’s recommended to segment network traffic more discreetly based on sensitivity levels as well.
 
Orchestrator Node Trust – Configure orchestrators to safeguard secure-by-default ensuring nodes have a persistent identity, gain accurate inventory of nodes and their network connections. Have the means in place to isolate/remove compromised nodes would not compromise others and finally, use authenticated network connections between cluster members and end-to-end encryption of intracluster traffic.

 Hunt for Vulnerabilities Within The Runtime Software – Monitor container runtime for vulnerabilities. Use tools to detect CVEs vulnerabilities and ensure orchestrators only allow deployments to properly maintained runtime.

 Unbounded Network Access from Containers – Control and monitor containers’ outbound network traffic as well as inter-container traffic. Use app-aware tools to gain visibility into inter-container traffic, as well as to dynamically generate rules used to filter traffic based on specific app characteristics. In addition, these tools should provide:
Automated container networking surfaces (both inbound ports and process port bindings)
Detection of traffic flows both between containers and other network entities
Detection of network anomalies (e.g.: unexpected traffic flows, port scanning, outbound access to potentially risky destination)
  
Insecure Container Runtime Configurations – Use tools/processes to continuously assess and automatically enforce configuration settings against CIS standards, for example. In addition, as an added control, consider using Mandatory Access Control (MAC) technologies to secure the host OS layer and ensure only specific files, path, processes and network sockets are accessible to containerized apps.
 
App Vulnerabilities – Use container-native tools to automatically profile containerized apps using behavioral analysis and build security profiles to be able to detect and prevent anomalous event at runtime, such as:
Invalid or unexpected process execution
Invalid or unexpected system calls
Changes to protected configuration files and binaries Writes to unexpected locations and file types Creation of unexpected network listeners
Traffic sent to unexpected network destinations Malware storage or execution

Further, containers should also be run with their root filesystems in read-only mode to make the containers more resilient to compromise. In addition, write privileges can be defined and monitored separately.

Rogue Containers – Create separate environments for development, test, production and other scenarios, each with specific controls to provide RBAC for container deployment and management activities.

In addition, container creation should be associated with individual user identities and logged to provide an activity audit trail.

Further, it is recommended to enforce baseline requirements for vulnerability management and compliance prior to deployment.
 
Shared Kernel – Do not mix containerized and non-containerized workloads on the same host instance. (e.g.: if a host is running a web server container, it should not also run a web server as a regularly installed component directly within the host OS). This will also make it easy to apply optimized countermeasures for container protection.

Host OS Component Vulnerabilities – Implement management practices and tools to validate the versioning of components provided for base OS management and functionality. Further, redeploy OS instances/apply updates (security and components-wise), to keep the OS up-to-date. Use managed “Container Optimised System” images where possible.

Monitor the multi-pod container YAML configuration. The Sidecar containers or initContainer may feature libraries, configuration or components which could put the application container at risk, through the notion of shared linux namespace, particularly the remapping of the shared volume binaries (if rw) between such containers may introduce application run-time vulnerabilities
 
Host File System Tampering – Ensure containers are running with a minimal set of file system permissions required. Very rarely should containers mount local file systems on a host. Instead, any file changes that containers need to persist to disk should be made within storage volumes specifically allocated for this purpose. In no case should containers be able to mount sensitive directories on a host’s file system, especially those containing configuration settings for the operating system. Lock down access such granular access as appropriate using the `SecurityContext`. Do not enable/run containers in Privileged:True mode.

Improper User Access Rights – Ensure all authentication to the OS is audited, as well as monitor and login anomalies and privileges escalation to be able identity, for example, anomalous access patterns to host and privileged commands to manipulate containers.

 
Redhat’s 10 layers of Container Security [4]

Container host multi-tenancy – The Host operating should be optimized to run containers such as Atomic, CoreOS.

Container content – Packages and libraries should be scanned and verified from trusted sources.

Container registries – An internal trusted registry should host internal application container images.

We recommend that you design your container image management and build process to take advantage of container layers to implement separation of control, so that your: 

Operations team manages base images 
Architects manage middleware, runtimes, databases and other such solutions using best-practices such as multi-stage docker image builds
Developers focus on application layers and just write code

Building containers – Building containers should be done with a CI/CD pipeline to ensure the security of the images and consistent build process for images. 

A best practice for application security is to integrate automated security testing into your CI process. For example, integrate:

Static Application Security Testing (SAST) and Dynamic Applications Security Testing (DAST) tools like HP Fortify and IBM AppScan
Scanners for real-time checking against known vulnerabilities like Black Duck Hub and JFrog Xray

Tools like these catalog the open source packages in your container, notify you of any known vulnerabilities and update you when new vulnerabilities are discovered in previously scanned packages.

Deploying containers – From a single container to an entire microservice architecture. The deployment process has several considerations.

Container orchestration – The orchestrator should be able to answer the following questions: 
Which containers should be deployed to which hosts?
Which host has more capacity?
Which containers need access to each other. How will they discover each other?
How do you control access to and management of shared resources, like network and storage?
How do you monitor each container’s  health in a given POD?
How do you automatically scale application capacity to meet demand?
How to enable developer self-service while also meeting security requirements?

Network isolation – A CNI should be chosen that supports network policies and allows for ingress/egress rules between namespaces.

Storage – Kubernetes provides plugins for persistent volumes. Their plugins have different capabilities and modes. For on-premise, volumes can be backed by technology such as NFS, Ceph and Gluster [6]

Application programming interface (API) management – API Access, Authorization and Authentication should be a critical part of the Container and Cluster operations. Applications such as SAML 2.0 or OpenID Connect-based authentication and web single sign-on should be used for AAA purposes. 

Federated clusters – As of Kubernetes 1.3 Cluster Federation allows one authentication method for multiple clusters. Running of multiple clusters allows applications to be highly available across data centers or available zones in data centers.

Cluster Setup

High level overview of the Cluster setup. Complete and detailed directions are provided here [8].


Image 1. Kubernetes Components High-Level Overview 
Services/Applications running on each node 
Masters:
Kube-apiserver – Kubernetes API server
Kube-controller-manager – Controller manager for Deployments, services etc. 
Kube-scheduler – Schedule the pods to the nodes

Nodes: 
Kubelet – Service that reports node and pod status to the API server
Docker/Container Runtime – Responsible for running the containers that are schedule to the node  
Kube-proxy – Responsible for updating the routing rules on the nodes 

Etcd:
Etcd – Backend data store for the API server


Cluster Size – Master nodes should always be an odd number as well as the etcd cluster, to be able to withstand loss of a node.

(N - 1) / 2 where n is the number of nodes in the cluster, so a 3 node cluster can withstand a loss of one node and still function. 

Certificates – All components should use X.509 client certificates to authenticate to the API server. The API server is protected by TLS certificates as well from a dedicated CA for Kubernetes. 

CA CERT – Put in on node where API Server runs, for example in /srv/kubernetes/ca.crt
CA Private Key
Master cert – Signed by CA_CERT, put in on node where Api Server runs, for example in /srv/kubernetes/server.crt
Master key – Put in on node where Api Server runs, for example in /srv/kubernetes/server.key
Kubelet cert and key
kube-controller-manager certificate and private key
kube-proxy certificate and private key
kube-scheduler certificate and private key

Namespaces – Use of Namespaces will logically organize the cluster. Namespaces can also have different RBAC privileges. Also it will allow for network isolation between pods. Namespaces allow for different quotas for cluster resources. 

Etcd – If possible Etcd should be external to the cluster. Some installations run Etcd on the same nodes as the masters. 

Worker Node preparation:  

Docker Install – Docker creates its own bridge during install but Kubernetes does not use this specific one so run: 
iptables -t nat -F
ip link set docker0 down
ip link delete docker0
Kubelet – When running HTTPS on the API Server make sure to update the Kubelet config on each node. 

Kube Proxy – All nodes must run the Kube proxy. 

--master=https://$MASTER_IP
--kubeconfig=/var/lib/kube-proxy/kubeconfig
Other Options to consider 
Enable auto-upgrades for your OS package manager, if desired
Configure log rotation for all node components
Setup liveness-monitoring using OS specific tools such as supervisord 
Setup volume plugin support – Install any client binaries for optional volume types, such as: 
glusterfs-client
NFS
Ceph 

6. Validate the cluster is set up properly – The Kubernetes github repo provides scripts to validate the setup of the cluster. Provided here [4]. 
	
Securing the Cluster

A Kubernetes Cluster has several components and all of them need to be secured to ensure cluster secure communication on a network. 
					
Master Access – All access to the master is over transport layer security (TLS)

API Access – Access to the API server is X.509 certificate or token-based

ETCD – Etcd is not exposed directly to the cluster




Image 2. Kubernetes Component Communication


Component Communication Breakdown 

CNI: Network Plugin in Kubelet that allows communication to the network to get IPs for Pods and Services.

gRPC: API to communicate API Server to ETCD, Controller Manager and Scheduler.

Kubelet – All K8s nodes have a kubelet that ensures that any pod assigned to it is running and configured in the desired state.

CRI (Container Runtime Interface) gRPC API compiled in kubelet which allows the kubelet to talk to container runtimes by using gRPC API.

The Container Runtime provider has to adapt it to CRI API to allow kubelet to talk to them by using OCI Standard (runc). Initially, Kubernetes was built on top of Docker as the container runtime. Soon after, CoreOS announced the rkt container runtime and wanted Kubernetes to support it as well. Kubernetes ended up supporting Docker and rkt, although this model wasn't very scalable in terms of adding new features or support for new container runtimes.

CRI consists of a protocol buffers and gRPC API, and libraries.

	
API Server – The API server should be protected with TLS certificates. 

Cluster – All communication paths from the cluster to the master terminate at the Api Server. 

Kubelet – The connections from the API server to the kubelet are used for:
Fetching logs for pods
Attaching (through kubectl) to running pods
Providing the kubelet’s port-forwarding functionality
These connections terminate at the kubelet’s HTTPS endpoint. By default, the Api Server does not verify the kubelet’s serving certificate, which makes the connection subject to man-in-the-middle attacks, and unsafe to run over untrusted and/or public networks. [1]
Api Server to nodes, pods and services

The connections from the Api Server to a node, pod or service default to plain HTTP connections and are therefore neither authenticated nor encrypted. They can be run over a secure HTTPS connection by prefixing https: to the node, pod or service name in the API URL, but they will not validate the certificate provided by the HTTPS endpoint nor provide client credentials so while the connection will be encrypted, it will not provide any guarantees of integrity. These connections are not currently safe to run over untrusted and/or public networks.[1]

The Center for Internet Security (CIS) publishes a Benchmark for Kubernetes giving best practices for configuring a deployment to use secure settings. If you are running Docker as the container runtime, CIS also publishes their Benchmark for Docker [13]. These benchmarks should be part of the normal Cluster operations and CI/CD practices to ensure your clusters are always secure. 
				
Cluster Operations 

Certificate rotation – Enable automatic certificate rotation on the API server. Default Certificates generally expire after a year but can be configured at the CA level.  

Start the kubelet with this flag 

The kubelet process accepts an argument --rotate-certificates that controls the kubelet automatically requesting a new certificate as the expiration of the certificate currently in use approaches.

Since certificate rotation is a beta feature, the feature flag must also be enabled with --feature-gates=RotateKubeletClientCertificate=true

The kube-controller-manager process accepts an argument --experimental-cluster-signing-duration that controls how long certificates will be issued for as well. The default is one year. 

Node Draining – Marking a node as unschedulable prevents new pods from being scheduled to that node, but does not affect any existing pods on the node, Pods that are running under Deployments, Services will be rescheduled on other nodes. This is useful as a preparatory step before a node maintenance and reboot. Run this command:
#kubectl cordon $NODENAME
Etcd Backups – etcd supports built-in snapshot. When running maintenance on a Etcd cluster make sure to back it up. The entire Kubernetes cluster information and state is stored in Etcd. Run the following command on a node in the cluster with this command: 
etcdctl snapshot save
ETCDCTL_API=3 etcdctl --endpoints $ENDPOINT snapshot save snapshotdb
# exit 0

# verify the snapshot
ETCDCTL_API=3 etcdctl --write-out=table snapshot status snapshotdb
+----------+----------+------------+------------+
|   HASH   | REVISION | TOTAL KEYS | TOTAL SIZE |
+----------+----------+------------+------------+
| fe01cf57 |       10 |          7 | 2.1 MB     |
+----------+----------+------------+------------+
Cluster Upgrades

Upgrade/Update the Master first and then the nodes. 

Kubernetes masters should be behind a load-balanced IP address, so the API server continues to work during upgrades. 

Make sure pods are managed by ReplicationController, Deployment or StatefulSet. Standalone pods won’t be Rescheduled when the node is drained. 

Implement Blue-Green Deployment strategy or also called as Node Pool. 

Cluster and Container Monitoring and Alerting

Image 3. Monitor levels in Kubernetes

Host Level Metrics (Cluster Utilization) – The Kubernetes API exposes nodes metrics which can be used in conjunction by leveraging a full fledged monitoring solution such as Prometheus, Heapster or InfluxDB and Grafana to monitor node-level CPU utilization, Memory Utilization vs Reservation, Disk Utilization, Network in/out and ultimately node status (Online vs DOWN).

Container Level Metrics (Container Utilization) – Open source tooling such as cAdvisor and Heapster offer capabilities to monitor pod-level metrics such as the above.

Application Metrics (APM) – APM monitoring can be unique to a respective application and provide deep insight as to what internal function calls are causing a potential bottleneck for an application – APM also offers AD teams to publish custom metrics / KPIs outside of the usual host-level metrics that operation teams are accustomed to alert on.

Log Aggregation (Avoid writing to files – do stdout/err) – Leverage a log-forwarder agent as a sidecar to push logs into a central store (e.g.: splunk agent, sumologic, loggly or FluentD) – Having access to application logs is imperative to application telemetry in conjunction with metrics. Application logs will allow operators and support personnel to identify whether or not programs are catching errors accordingly or spitting out stack-traces for unhandled exceptions.

Node Problem Detector – Node problem detector is a DaemonSet monitoring the node health. It collects node problems from various daemons and reports them to the API server as NodeCondition and Event. It is recommended to run the node problem detector in your cluster to monitor the node health. 

Have Visibility of Readiness and Liveness Checks – Kubernetes Pods use Readiness and liveness Checks to ensure the health of the pods.
livenessProbe: Indicates whether the Container is running. If the liveness probe fails, the kubelet kills the Container, and the Container is subjected to its restart policy. If a Container does not provide a liveness probe, the default state is Success [17].
readinessProbe: Indicates whether the Container is ready to service requests. If the readiness probe fails, the endpoints controller removes the Pod’s IP address from the endpoints of all Services that match the Pod. The default state of readiness before the initial delay is Failure. If a Container does not provide a readiness probe, the default state is Success. [17].
Alerting
Alert on application metrics (e.g.: API Latency) – Working in a Kubernetes Environment would not change how the APM is being used in the application. Applications can still provide metrics via the SDK or other integrations included in the APM. 

Alert on system calls (Count of CrashLoopBackOff) – Pods have statuses that indicate issues with it. During deployments and everyday operations, these should be monitoring and alerting on. 

Node Availability – The Kubelet continually communicates with the API server. When the node goes down or the kubelet process goes down on the host, the API server can not schedule pods onto the node. Node availability should be alerted on. 

Node Host Level Metrics (Load Avg, Mem/CPU, FS, etc.) – Normal node metrics should be alerted per team’s operating SLA’s. 

Cluster Authentication

Authentication Mechanisms
X509 Client Certs
Static Token File
Static Password file
Service Account Token

Implement a basic token-based authentication protocol
anonymous auth is enabled, but anonymous users’ ability to call the kubelet API should be limited
bearer token auth is enabled, but arbitrary API users’ (like service accounts) ability to call the kubelet API should be limited by Authorization model in the next section
client certificate auth is enabled, but only some of the client certificates signed by the configured CA should be allowed to use the kubelet API
Group and isolate cluster resources by using Namespace as mentioned previously in this document. 
Integrate your existing LDAP

Leverage your existing Organization LDAP to manage your users and roles. This can be achieved using OpenID as described in Image 4. 



	





Image 4.  Kubectl Authentication with OpenID Connect.

Requirements for an IDP to use with Kubernetes 
Support OpenID connect discovery; not all do
Run in TLS with non-obsolete ciphers
Have a CA signed certificate (even if the CA is not a commercial CA or is self signed)


Cluster Authorization

Grant role-based access to cluster resources. 

ClusterRole – Set of rules that determine the permission scoped at the cluster level.
Clusterrolebinding – Grants the privileges defined in a clusterRole
kind: ClusterRole
apiVersion: rbac.authorization.k8s.io/v1
metadata:
  # "namespace" omitted since ClusterRoles are not namespaced
  name: secret-reader
rules:
- apiGroups: [""]
  resources: ["secrets"]
  verbs: ["get", "watch", "list"]
# This cluster role binding allows anyone in the "manager" group to read secrets in any namespace.
kind: ClusterRoleBinding
apiVersion: rbac.authorization.k8s.io/v1
metadata:
  name: read-secrets-global
subjects:
- kind: Group
  name: manager # Name is case sensitive
  apiGroup: rbac.authorization.k8s.io
roleRef:
  kind: ClusterRole
  name: secret-reader
  apiGroup: rbac.authorization.k8s.io

Grant role-based access to users in the namespace 
Role – Set of rules that determine the permission scoped at the namespace level 
Rolebinding – Grants the privileges defined in a Role
          kind: Role
	apiVersion: rbac.authorization.k8s.io/v1
	metadata:
 	 namespace: default
	 name: pod-reader
	rules:
	- apiGroups: [""] # "" indicates the core API group
  	resources: ["pods"]
  	verbs: ["get", "watch", "list"]
# This role binding allows "jane" to read pods in the "default" namespace.
	kind: RoleBinding
	apiVersion: rbac.authorization.k8s.io/v1
	metadata:
	  name: read-pods
	  namespace: default
	subjects:
	- kind: User
	  name: jane # Name is case sensitive
	  apiGroup: rbac.authorization.k8s.io
	roleRef:
	  kind: Role #this must be Role or ClusterRole
	  name: pod-reader # this must match the name of the Role or ClusterRole you wish to bind to
	  apiGroup: rbac.authorization.k8s.io
Create a service account, role and rolebinding per Kubernetes application.

A service account provides an identity for processes that run in a Pod. Every       namespace has a default service account resource called “default”. “ kubectl get serviceAccounts”         

Set a reasonable user session timeout.

Cluster Troubleshooting 

Master Node Checks – All services for the Kubernetes components run as services on the Master nodes. To check the status of all components run.


#for SERVICES in etcd kube-apiserver kube-controller-manager kube-scheduler; do 
    echo --- $SERVICES --- ; systemctl is-active $SERVICES ;
    systemctl is-enabled $ SERVICES; echo “”; 
done
If any of the master or node systemd services are disabled or failed, try to enable or activate the service.						
Check the systemd journal on the system where a service is failing to try to pinpoint the problem. Use the journalctl with the command for the service. For example:	
# journalctl -l -u kubelet
# journalctl -l -u kube-apiserver
If the services still don’t start, check that each service’s configuration file is set up properly.

Worker node checks

# kubectl get nodes
NAME                                 STATUS    AGE
gke-cka-default-pool-9f1b2d0f-8n26   Ready     9m
gke-cka-default-pool-9f1b2d0f-r8hs   Ready     9m
gke-cka-default-pool-9f1b2d0f-tlft   Ready     9m
#kubectl describe nodes
Log locations
Master
/var/log/kube-apiserver.log – API Server, responsible for serving the API
/var/log/kube-scheduler.log – Scheduler, responsible for making scheduling decisions
/var/log/kube-controller-manager.log – Controller that manages replication controllers
Worker Nodes
/var/log/kubelet.log – Kubelet, responsible for running containers on the node
/var/log/kube-proxy.log – Kube Proxy, responsible for service load balancing

Application Troubleshooting 
kubectl Commands
Kubectl get – List resources
Kubectl describe – Show detailed information about a resource
Kubectl logs – Print the logs from a container in a pod
kubectl exec – Execute a command on a container in a pod
BusyBox – Another common practice is use busybox to troubleshoot issues inside the cluster. The command below will start a busybox container in the cluster and drop you into a shell to run diagnostics. 
kubectl run -i --tty busybox --image=busybox -- sh
Kubernetes Cheat sheet – A list of common Kubernetes commands is available [15]
Common pods failures
Pending status – The Kubernetes scheduler is trying to schedule the pod on a node. It is generally an issue with capacity. kubectl describe pod $PODNAME will output more information, or kubectl describes nodes. 
CrashLoopFeedback – This is a common issue where a pod was scheduled but the backend application crashed. The best way to troubleshoot this issue is to perform a kubectl logs $PODNAME; If it’s evident that the crash isn’t application-specific, then performing a kubectl describe pod $PODNAME is the next best step.


Sources

Kubernetes Cluster Communication,  https://kubernetes.io/docs/concepts/architecture/master-node-communication/#apiserver-to-nodes-pods-and-services
Kubernetes TLS bootstrapping, https://kubernetes.io/docs/reference/command-line-tools-reference/kubelet-tls-bootstrapping/
Google hardening your Cluster, https://cloud.google.com/kubernetes-engine/docs/how-to/hardening-your-cluster
Redhat's 10 layers of Container Security, https://www.redhat.com/cms/managed-files/cl-container-security-openshift-cloud-devops-tech-detail-f7530kc-201705-en.pdf
Kubernetes authorization, https://v1-11.docs.kubernetes.io/docs/reference/access-authn-authz/authentication
Kubernetes Storage, https://kubernetes.io/docs/concepts/storage/persistent-volumes/ 
Kubernetes Namespaces, https://github.com/kubernetes/community/blob/master/contributors/design-proposals/architecture/namespaces.md#phases
Kubernetes Setup from Scratch, https://kubernetes.io/docs/setup/scratch
Kubernetes Cluster validation Script, https://github.com/kubernetes/kubernetes/blob/master/cluster/validate-cluster.sh
Redhat Getting Started with Containers, https://access.redhat.com/documentation/en-us/red_hat_enterprise_linux_atomic_host/7/pdf/getting_started_with_containers/Red_Hat_Enterprise_Linux_Atomic_Host-7-Getting_Started_with_Containers-en-US.pdf
Redhat Getting Started with Kubernetes, https://access.redhat.com/documentation/en-us/red_hat_enterprise_linux_atomic_host/7/pdf/getting_started_with_kubernetes/Red_Hat_Enterprise_Linux_Atomic_Host-7-Getting_Started_with_Kubernetes-en-US.pdf
Center For Internet Security - Kubernetes Benchmarks, https://www.cisecurity.org/benchmark/kubernetes/
Center For Internet Security - Docker Benchmarks, https://www.cisecurity.org/benchmark/docker/
Etcd Backups, https://kubernetes.io/docs/tasks/administer-cluster/configure-upgrade-etcd/
Kubernetes Cheatsheet, https://kubernetes.io/docs/reference/kubectl/cheatsheet/
Kubernetes Probes, https://kubernetes.io/docs/concepts/workloads/pods/pod-lifecycle/#container-probes
Node problem Detector,https://kubernetes.io/docs/tasks/debug-application-cluster/monitor-node-health/



