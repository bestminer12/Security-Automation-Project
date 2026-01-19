# Public EC2 Exposure Detection & Guardrail Automation     

## 1. 프로젝트 개요

본 프로젝트는 AWS 환경에서 **IaC(Terraform) 기반 인프라 운영 중 발생할 수 있는 보안 설정 실수**를
실시간으로 탐지하고, 위험도가 높은 경우 자동으로 대응하는 **Cloud Security Guardrail Architecture**를 구현하는 것을 목표로 한다.

특히 퍼블릭 클라우드 환경에서 자주 발생하는 **Public Exposure 사고 패턴**을 중심으로,
탐지 → 판단 → 대응의 전체 흐름을 설계한다.

---

## 2. 위협 시나리오 (Threat Scenario)

### 상황 정의
- Terraform으로 EC2 인스턴스 생성
- 퍼블릭 IP 할당
- 디폴트 Security Group에 SSH(22/tcp)를 0.0.0.0/0으로 오픈
- 이는 운영 실수 또는 IaC 설계 미흡으로 인해 실제로 자주 발생하는 보안 사고 유형

### 의도
IaC 환경이라 하더라도 사람의 실수는 발생할 수 있으며,  
이를 **자동으로 탐지하고 통제할 수 있는 Guardrail 체계가 필요함**을 증명한다.

---

## 3. 탐지 구조 (Detection)

### 이벤트 소스
- AWS CloudTrail

### 탐지 대상 이벤트
- `AuthorizeSecurityGroupIngress`

### 탐지 조건
- `cidrIp = 0.0.0.0/0`
- `fromPort = 22`

> Terraform, AWS Console 등 변경 경로와 무관하게  
> 모든 인프라 변경은 CloudTrail에 기록되므로 IaC 환경에서도 탐지가 가능하다.

---

## 4. 이벤트 흐름 (Event Flow)

1. Security Group 인바운드 규칙 변경 발생
2. CloudTrail 로그 생성
3. EventBridge Rule이 조건에 맞는 이벤트 필터링
4. Lambda 함수 호출

---

## 5. Lambda 판단 로직 (Risk Assessment)

Lambda는 단순한 자동화가 아니라 **보안 엔지니어의 판단 로직을 코드로 구현**한다.

### 이벤트 분석 항목
- 대상 Security Group ID
- 포트 번호
- CIDR 범위
- 퍼블릭 IP 여부
- 변경 주체 (IAM User / Role)

### 리스크 점수 모델 예시
- 퍼블릭 IP 사용: +30
- 0.0.0.0/0 오픈: +40
- SSH(22/tcp): +30

총 점수: 100점 (Critical)

> 점수 기반 구조로 설계하여 향후 다른 리스크 유형으로 확장 가능

---

## 6. 대응 정책 (Response Policy)

### Critical 등급 (본 프로젝트 대상)
- SSH(22/tcp) + 0.0.0.0/0
- 운영 환경에서 정당화되기 어려운 설정

### 자동 대응 수행
1. 해당 Security Group 인바운드 룰 자동 제거
2. Slack / Email 알림 전송

### Slack 알림 예시
[SECURITY ALERT] Public Exposure Detected 🚨

Account ID: 123456789012
Region: ap-northeast-2
Resource Type: Security Group
Security Group ID: sg-0a1b2c3d4e5f67890
Security Group Name: public-exposure-sg

Exposed Port(s):
- TCP 22 (SSH)
- Source: 0.0.0.0/0

Affected Resource:
- EC2 Instance ID: i-0123456789abcdef0
- Public IP: 13.xxx.xxx.xxx

Risk Level: HIGH
Detection Time (UTC): 2026-01-20 02:13:45

Action Taken:
- ❌ Public inbound rule REMOVED
- 🔒 Security Group restricted to internal CIDR

Triggered By:
- CloudTrail event: AuthorizeSecurityGroupIngress
- Automated Response: AWS Lambda

Please review if this exposure was intentional.
---  

## 7. 자동 차단 설계 근거

- SSH 0.0.0.0/0은 서비스 중단 위험이 거의 없음
- 차단으로 인한 영향도보다 보안 위험도가 압도적으로 큼
- 따라서 Guardrail 성격의 자동 차단이 합리적

> 반면, 443 포트나 DB 퍼블릭 노출은 승인 기반(Manual Approval)으로 확장 가능

---

## 8. Terraform 설계 포인트

Terraform으로 의도적으로 **보안 취약한 설정**을 생성하여
Guardrail이 이를 자동으로 무력화하는 구조를 구현한다.

```hcl
resource "aws_security_group" "example" {
  ingress {
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }
}
