
# AWS Credential Exposure Incident Response Simulation

## 📌 Project Overview
This project simulates a real-world cloud security incident involving exposed AWS access keys (AKIA) and demonstrates how to detect, analyze, and respond to potential misuse.

The goal of this project is to showcase practical incident response (IR) skills in a cloud environment, focusing on AWS credential exposure scenarios that frequently lead to real security breaches such as crypto-mining or unauthorized resource usage.

---

## 🎯 Objectives
- Simulate AWS access key exposure scenario
- Detect suspicious activities using AWS logs
- Perform incident analysis based on CloudTrail events
- Demonstrate response strategy and remediation planning
- Build a realistic IR workflow applicable to real-world environments

---

## 🛠️ Environment
- AWS CloudTrail
- AWS IAM
- AWS EC2
- AWS Lambda (for alert simulation)
- Amazon EventBridge
- Discord Webhook (alerting)
- GitHub (documentation)

---

## 🚨 Scenario
1. AWS access key is created and assumed to be exposed.
2. Suspicious API activity is observed (e.g., RunInstances).
3. Logs are analyzed via CloudTrail.
4. Potential crypto-mining activity is investigated.
5. Incident response actions are documented.

---

## 🔍 Detection Method
- Monitoring CloudTrail for:
  - `CreateAccessKey`
  - `RunInstances`
  - Unusual region usage
- Event-based alerting using EventBridge + Lambda
- Alert delivery via Discord webhook

---

## 🧯 Response & Remediation
- Identify compromised credentials
- Key deactivation and rotation strategy
- Resource termination (if malicious instances detected)
- Policy review and least-privilege enforcement
- Recommendations for prevention

---

## 📊 Key Learnings
- Importance of credential hygiene in AWS
- Realistic cloud IR workflow design
- Log-based detection strategy
- Security automation for faster response

---

