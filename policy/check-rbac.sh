#!/bin/bash

echo "Scanning RBAC policies..."

if grep -r 'verbs: \["\*"\]' kubernetes-security-automation-architecture/k8s; then
  echo "Over-privileged RBAC detected"
  exit 1
fi

echo "RBAC policy check passed"