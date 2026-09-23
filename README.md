# HoneySentinel

### AI-Driven Deception Honeypot & Threat Intelligence System for Campus Networks

HoneySentinel is a cybersecurity monitoring platform that combines a deception-based SSH honeypot, backend services, machine learning-based threat classification, MITRE ATT&CK mapping, risk analysis, and a centralized SOC dashboard.

The system is designed to capture suspicious activity in a controlled environment, analyze attacker commands, and present actionable security information through a centralized dashboard.

---

## 🚀 Project Overview

Traditional cybersecurity labs often depend on static datasets, which provide limited exposure to real-time attack activity.

HoneySentinel addresses this gap by providing a controlled honeypot environment where suspicious interactions can be captured and analyzed.

The system:

- Deploys an SSH honeypot using Cowrie
- Captures login attempts, commands, sessions, and attack events
- Forwards Cowrie logs to the backend
- Stores security data in MySQL
- Classifies commands using a hybrid Rule-Based + Machine Learning engine
- Uses Logistic Regression for ML-based threat classification
- Maps recognized behaviors to MITRE ATT&CK techniques
- Assigns severity and risk scores
- Generates security recommendations
- Provides a centralized SOC dashboard
- Supports PDF security report generation

---

## 🏗️ System Architecture

```text
                  Attacker / Simulated Attacker
                              |
                              v
                    +------------------+
                    |  Cowrie Honeypot |
                    |    Kali Linux    |
                    +------------------+
                              |
                         cowrie.json
                              |
                              v
                    +------------------+
                    | Python Log       |
                    | Forwarder        |
                    +------------------+
                              |
                         REST / HTTP
                              |
                              v
                    +------------------+
                    | Attack Service   |
                    | Spring Boot      |
                    | Port: 8081       |
                    +------------------+
                              |
                              v
                    +------------------+
                    |     MySQL        |
                    |   honeypot_db    |
                    +------------------+
                       /       |       \
                      /        |        \
                     v         v         v
              Analytics       AI       Reports
              Service      ML Service     |
              :8083       :8000/:5000    |
                     \        |          /
                      \       |         /
                       v      v        v
                    +------------------+
                    |   API Gateway    |
                    |  Spring Boot     |
                    |    :8080        |
                    +------------------+
                              |
                              v
                    +------------------+
                    | React + Vite SOC |
                    |    Dashboard     |
                    |      :5173       |
                    +------------------+