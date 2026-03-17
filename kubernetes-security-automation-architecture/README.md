# Kubernetes Security Automation Architecture

## Overview

This project demonstrates a cloud-native security automation architecture built on Kubernetes.

The goal of this project is to move beyond event-driven cloud security automation and design policy-based security controls for containerized workloads.

This architecture enforces security guardrails during the CI pipeline and Kubernetes deployment stages.

---

## Objectives

- Prevent deployment of vulnerable container images
- Enforce least-privilege RBAC policies
- Block privileged container execution
- Restrict lateral movement using NetworkPolicy
- Demonstrate automated security enforcement in Kubernetes

---

## Architecture
