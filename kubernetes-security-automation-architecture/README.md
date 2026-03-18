# Kubernetes Security Automation Architecture

This project demonstrates how Kubernetes security risks can be mitigated using automated security controls across both runtime and CI/CD pipeline layers.

The architecture simulates realistic attack scenarios such as service account abuse, lateral movement between namespaces, privileged container escalation, vulnerable image deployment, and over-privileged RBAC configuration.

Security controls are implemented using Kubernetes native mechanisms and DevSecOps pipeline automation to prevent, detect, and block risky configurations before deployment.

---

## Architecture Overview

This project implements security controls across two major layers:

### Runtime Security Layer (Cluster Level)

- RBAC Least Privilege Enforcement  
- Network Segmentation using NetworkPolicy  
- Pod Security Admission for Privileged Container Blocking  

### CI/CD Security Automation Layer (Pipeline Level)

- Vulnerable Container Image Detection using Trivy  
- Over-Privileged RBAC Detection using Policy Script  
- Automatic Deployment Failure on Security Violation  

---

## Threat Scenario Simulation

The project simulates a full attacker lifecycle inside a Kubernetes cluster.

### Scenario 1 — ServiceAccount Foothold

A service account with limited permissions is created to simulate attacker foothold.

The account can:

- get pods
- list services

But cannot:

- create pods
- delete services

This demonstrates reconnaissance capability without destructive permissions.

Validation example:
kubectl auth can-i get pods -n dev –as=system:serviceaccount:dev:dev-readonly-sa
yes

kubectl auth can-i create pods -n dev –as=system:serviceaccount:dev:dev-readonly-sa
no

---

### Scenario 2 — Namespace Lateral Movement

Initial state:

A pod in the `prod` namespace is able to access a service in the `dev` namespace.
kubectl exec -n prod test-client – wget -qO- http://
After applying NetworkPolicy:

Traffic from `prod` to `dev` is blocked.

This demonstrates east-west traffic segmentation.

---

### Scenario 3 — Privilege Escalation Attempt

An attacker attempts to deploy a privileged container.

Pod Security Admission baseline policy blocks the deployment.
Error: violates PodSecurity “baseline”
securityContext.privileged=true is not allowed
This prevents node-level compromise.

---

### Scenario 4 — Vulnerable Image Deployment Attempt

A vulnerable Node.js container image is intentionally built.

Trivy scan runs in GitHub Actions pipeline.

If HIGH or CRITICAL vulnerabilities are detected:

Deployment pipeline fails automatically.

Pipeline logic:
docker build -t vuln-app ./kubernetes-security-automation-architecture/docker

Trivy scan:
severity: HIGH,CRITICAL
exit-code: 1
This prevents vulnerable workloads from reaching runtime.

---

### Scenario 5 — Over-Privileged RBAC Deployment Attempt

A dangerous RBAC role is defined with wildcard permissions.
verbs: [””]
resources: [””]
apiGroups: [”*”]
A custom policy script runs in CI pipeline:
grep -r ‘verbs: "\*"’ kubernetes-security-automation-architecture/k8s
If detected:

Pipeline exits with code 1 and deployment is blocked.

GitHub Actions result:
Over-privileged RBAC detected
Process completed with exit code 1
This enforces governance and prevents risky privilege escalation paths.

---

## Security Control Mapping

| Threat | Control | Layer |
|------|--------|------|
| ServiceAccount abuse | RBAC least privilege | Runtime |
| Lateral movement | NetworkPolicy segmentation | Runtime |
| Privileged container escalation | Pod Security Admission | Runtime |
| Vulnerable image deployment | Trivy scan | CI/CD |
| Over-privileged RBAC | Policy automation script | CI/CD |

---

## Project Structure
```bash
kubernetes-security-automation-architecture/
├── docker/
│   ├── Dockerfile
│   └── app.js
├── k8s/
│   ├── namespace.yaml
│   ├── dev-readonly-serviceaccount.yaml
│   ├── dev-readonly-role.yaml
│   ├── dev-readonly-rolebinding.yaml
│   ├── network-policy-deny.yaml
│   ├── privileged-pod.yaml
│   ├── overprivileged-role.yaml
│   └── test-client.yaml
├── policy/
│   └── check-rbac.sh
├── .github/
│   └── workflows/
│       ├── trivy.yml
│       └── rbac.yml
└── README.md
```
---

## Key Learning Outcomes

- Demonstrates realistic Kubernetes attack paths and mitigations  
- Shows how runtime security controls and CI pipeline security must work together  
- Implements security automation that prevents insecure deployments  
- Applies least privilege and network segmentation principles  
- Builds a cloud incident response oriented architecture  

---

## Future Improvements

- OPA Gatekeeper policy enforcement  
- Falco runtime threat detection  
- Admission Controller mutation policies  
- Container image signing and verification  
- Centralized alerting integration (Slack / Discord)

---

## Conclusion

This project highlights how Kubernetes environments can be protected using layered security automation.

By combining runtime controls and CI pipeline enforcement, risky configurations are blocked before reaching production workloads.

The architecture reflects real-world cloud security and incident response scenarios.
