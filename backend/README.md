# 🛡️ Honeypot AI Microservices Architecture

An enterprise-grade, distributed Microservices & AI Threat Intelligence platform for Cowrie Honeypots, complete with real-time attack telemetry, MITRE ATT&CK categorization, automated mitigation generation, and a modern SOC Dashboard (**HoneySentinel**).

---

## 🏛️ Microservices Architecture

```
                    ┌────────────────────────────────────────────────────────┐
                    │      HoneySentinel SOC Frontend (React 18 / Vite)      │
                    │               http://localhost:5173                    │
                    └───────────────────────────┬────────────────────────────┘
                                                │ REST API / JSON
                                                ▼
                    ┌────────────────────────────────────────────────────────┐
                    │               API GATEWAY (Spring Boot)                │
                    │                 http://localhost:8080                  │
                    └───────┬───────────────────┬───────────────────┬────────┘
                            │                   │                   │
             ┌──────────────┴─────┐  ┌──────────┴─────────┐  ┌──────┴──────────────┐
             │   ATTACK SERVICE   │  │ ANALYTICS SERVICE  │  │   AI / ML SERVICE   │
             │   (Port: 8081)     │  │   (Port: 8083)     │  │   (Port: 8000)      │
             │  Honeypot Logs,    │  │  KPIs, Timeline,   │  │  MITRE ATT&CK,      │
             │  Sessions & Dumps  │  │  Geo Threat Stats  │  │  Risk Scoring (0-10)│
             └──────────────┬─────┘  └──────────┬─────────┘  └─────────────────────┘
                            │                   │
                            ▼                   ▼
                    ┌─────────────────────────────────────┐
                    │        MySQL Database (3306)        │
                    │             honeypot_db             │
                    └─────────────────────────────────────┘
```

---

## 🚀 How to Run in Eclipse IDE / Spring Tool Suite (STS)

### Step 1: Import into Eclipse
1. Open Eclipse IDE.
2. Click **`File`** ➔ **`Import...`** ➔ **`Maven`** ➔ **`Existing Maven Projects`**.
3. Browse to the root project directory: `D:\PROJECT\HONEYPOT AI DB`.
4. Eclipse will automatically detect all 4 Maven submodules:
   - `honeypot-microservices-parent` (Root)
   - `discovery-service`
   - `attack-service` (`backend`)
   - `analytics-service`
   - `api-gateway`
5. Click **Finish**.

---

### Step 2: Run the Microservices in Eclipse
Right-click each main class and select **`Run As ➔ Spring Boot App`** (or **`Run As ➔ Java Application`**) in the following order:

| Order | Service | Main Application Class | Port | Health / UI Endpoint |
| :---: | :--- | :--- | :---: | :--- |
| **1** | **`discovery-service`** | `DiscoveryServiceApplication.java` | `8761` | [http://localhost:8761](http://localhost:8761) |
| **2** | **`attack-service`** | `BackendApplication.java` | `8081` | [http://localhost:8081/api/attacks/health](http://localhost:8081/api/attacks/health) |
| **3** | **`analytics-service`** | `AnalyticsApplication.java` | `8083` | [http://localhost:8083/api/dashboard/stats](http://localhost:8083/api/dashboard/stats) |
| **4** | **`api-gateway`** | `ApiGatewayApplication.java` | `8080` | [http://localhost:8080/health](http://localhost:8080/health) |

---

### Step 3: Run the AI / ML Threat Intelligence Service
In terminal or Eclipse PyDev:
```bash
cd "D:\PROJECT\HONEYPOT AI DB\ml-service"
python main.py
```
*Service runs at [http://localhost:8000](http://localhost:8000)*

---

### Step 4: Run the HoneySentinel Frontend
```bash
cd "D:\PROJECT\HoneySentinelnew\HoneySentinel"
npm run dev
```
*Open [http://localhost:5173](http://localhost:5173) in your browser.*

---

### Step 5: (Optional) Seed Real Attack Data
To simulate Cowrie SSH brute-force attacks, malware downloads, and executed shell commands:
```bash
cd "D:\PROJECT\HONEYPOT AI DB"
python seed_honeypot_data.py
```

---

## 📡 REST API Catalog (Accessible via Gateway on `http://localhost:8080`)

### 1. Ingestion & Attack Management (`/api/attacks/**`, `/api/logs/**`)
| Method | Endpoint | Description |
| :--- | :--- | :--- |
| `POST` | `/api/attacks/ingest` | Ingest Cowrie honeypot event JSON. |
| `POST` | `/api/logs` | Ingest raw attack log. |
| `GET` | `/api/attacks/sessions` | List all attacker sessions with IP and protocol. |
| `GET` | `/api/attacks/sessions/{id}/details` | Get full timeline, commands, and credentials for session. |
| `GET` | `/api/attacks/commands` | List all hacker shell commands executed in sandbox. |
| `GET` | `/api/attacks/credentials` | List all stolen username/password brute force attempts. |
| `GET` | `/api/attacks/credentials/top` | Top 10 targeted credentials. |
| `GET` | `/api/attacks/downloads` | List captured malware downloads and SHA256 hashes. |

### 2. AI Threat Intelligence (`/api/ai/**`)
| Method | Endpoint | Description |
| :--- | :--- | :--- |
| `POST` | `/api/ai/classify-command` | Classify single shell command with MITRE ATT&CK categorization. |
| `POST` | `/api/ai/analyze-session` | Compute risk score (0-10), threat level, and confidence. |
| `GET` | `/api/ai/reputation/{ip}` | Lookup IP reputation, ASN, TOR/VPN exit node detection. |
| `GET` | `/api/ai/analysis/summary` | Overall AI classification and recommended security posture. |
| `POST` | `/api/ai/generate-mitigation` | Generate iptables, UFW, and fail2ban rules. |

### 3. Analytics & Dashboard (`/api/dashboard/**`)
| Method | Endpoint | Description |
| :--- | :--- | :--- |
| `GET` | `/api/dashboard/stats` | High-level KPI counters (Total Attacks, Failed Logins, IPs). |
| `GET` | `/api/dashboard/timeline` | 24-hour attack frequency time series for Recharts line chart. |
| `GET` | `/api/dashboard/recent-logs` | Formatted attack log feed for table view. |
| `GET` | `/api/dashboard/system-status` | Microservices health status. |

---

## 🗄️ Database Schema (`honeypot_db`)
- `attack_sessions`: Tracks source IP, duration, protocol, geo location, login success/failure.
- `attack_logs`: Raw Cowrie JSON event storage.
- `attack_events`: Atomic event audit log.
- `command_logs`: Shell commands executed in the honeypot container with risk rating.
- `credential_attempts`: Username and password dictionary attack pairs.
- `downloaded_files`: Malicious binaries, scripts, download URLs, and SHA256 hashes.
- `ai_analysis`: Automated threat intelligence verdicts, confidence %, and mitigations.
