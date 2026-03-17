# Kubernetes Security Automation Architecture

## Overview

This project demonstrates a cloud-native security architecture focused on runtime security controls and build-time security automation in Kubernetes.

The objective is to move beyond basic workload deployment and implement security guardrails that reduce blast radius, enforce least privilege, and prevent insecure container deployment.

The environment is built using a local Kubernetes cluster (Kind) to enable cost-efficient security experimentation and architecture validation.

---

## Architecture Goals

- Implement namespace-level workload isolation  
- Enforce least-privilege access using Kubernetes RBAC  
- Prevent east-west lateral movement using NetworkPolicy  
- Block insecure container configurations using Pod Security Admission  
- Integrate container image vulnerability scanning into CI pipeline  
- Demonstrate security automation design suitable for DevSecOps environments  

---

## Environment

- Kubernetes (Kind – Local Cluster)
- Docker
- Trivy
- GitHub Actions
- kubectl
- Nginx sample workload

---

## Project Structure
kubernetes-security-automation-architecture/
├── k8s/
├── docker/
├── ci/
├── screenshots/
├── threat-model/
└── README.md
---

## Security Controls Implemented

### 1. Namespace Isolation

Two namespaces were created to simulate environment separation:

- dev
- prod

This design reduces blast radius and allows namespace-scoped security enforcement.

---

### 2. Least Privilege RBAC

A dedicated ServiceAccount was created with read-only permissions in the dev namespace.

Security benefits:

- Prevents unauthorized resource modification  
- Enables scoped access control  
- Supports principle of least privilege  

Validation was performed using: kubectl auth can-i
---

### 3. NetworkPolicy – Lateral Movement Prevention

A NetworkPolicy was implemented to restrict ingress traffic to the nginx workload.

This prevents unauthorized east-west communication between namespaces.

Security impact:

- Limits attacker movement after initial compromise  
- Reduces internal attack surface  
- Enables micro-segmentation  

---

### 4. Pod Security Admission Enforcement

The restricted Pod Security Admission profile was enforced on the prod namespace.

This blocks:

- Privileged containers  
- Host access configurations  
- Unsafe security contexts  

This control prevents container breakout risks and enforces secure workload deployment standards.

---

## Container Image Security (CI Integration)

Container image scanning is integrated using Trivy.

Pipeline behavior:

- Docker image is built during CI
- Trivy scans image vulnerabilities
- CI fails if HIGH or CRITICAL vulnerabilities are detected

Security benefits:

- Prevents insecure images from reaching runtime  
- Shifts security validation to build phase  
- Enables DevSecOps automation  

---

## Threat Model

Threat scenarios considered:

### Privileged Container Risk
- Host resource access  
- Kernel capability abuse  
- Container escape potential  

### Lateral Movement Risk
- Cross-namespace service discovery  
- Internal network pivoting  

### RBAC Over-Privilege Risk
- Excessive API permissions  
- Unauthorized resource modification  

Mitigations implemented through:
- PSA enforcement  
- Network segmentation  
- Least privilege role design  

---

## Screenshots

Security validation evidence is available in the screenshots/ directory.

Examples:

- Namespace creation
- RBAC access validation
- NetworkPolicy traffic blocking
- PSA privileged pod rejection
- Trivy vulnerability scan results

---

## Future Improvements

- Policy as Code enforcement (Kyverno / OPA Gatekeeper)
- Runtime threat detection integration
- Security alert pipeline integration
- Automated rollback on policy violations

---

## Conclusion

This project demonstrates how Kubernetes security controls can be combined with CI security automation to build a practical DevSecOps security architecture.

It focuses not only on deploying workloads but on preventing insecure deployment patterns and reducing attack surface through automated guardrails.
