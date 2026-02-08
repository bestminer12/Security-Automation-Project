# AWS S3 Security Automation

## 📌 Overview

This project demonstrates an **event-driven security detection and auto-remediation pipeline for Amazon S3**, built with Terraform and AWS serverless services.

The goal is to simulate realistic cloud security incidents such as:

- Public S3 bucket exposure  
- Suspicious object uploads (webshell-like files)  
- Misconfigurations leading to data exposure  

and automatically detect and respond to them.

This project is designed as a **Cloud Incident Response (IR) and Security Automation portfolio**.

---

## 🎯 Objectives

- Detect S3 misconfigurations and risky behaviors  
- Simulate real-world attack scenarios  
- Implement automated remediation  
- Build a practical Security Automation use case  
- Showcase DevSecOps + IR skills for global roles  

---

## 🧩 Architecture

Event-driven architecture using:

S3 → CloudTrail → EventBridge → Lambda → Auto-remediation + Alerting

### Detection Scenarios

1. **Public Exposure Detection**
   - Detects bucket policy or ACL changes enabling public access
   - Automatically blocks public access

2. **Suspicious File Upload Detection**
   - Detects uploads of files like:
     - `.php`, `.jsp`, `.aspx`, `.exe`
     - filenames containing `shell`, `backdoor`, `cmd`
   - Moves objects to a quarantine bucket or tags them

---

## ⚙️ Tech Stack

- AWS S3  
- AWS Lambda (Python)  
- AWS EventBridge  
- AWS CloudTrail (Data Events)  
- Terraform (IaC)  
- GitHub Actions (optional CI/CD)  
- Discord Webhook (alerting)

---

## 📁 Project Structure
