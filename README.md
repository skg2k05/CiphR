# CiphR

### Android APK Fraud Intelligence & Campaign Correlation Platform

CiphR is a security analysis platform for investigating suspicious Android applications, extracting static intelligence, assigning explainable risk, mapping observed indicators to **MITRE ATT&CK for Mobile**, and correlating related APKs into potential fraud campaigns.

It combines a **FastAPI analysis backend** with a **React-based analyst dashboard** to turn an uploaded APK into structured evidence, risk findings, threat intelligence, campaign relationships, and analyst-oriented threat reports.

> **CiphR is a static-analysis platform. Uploaded APKs are analyzed as untrusted files and are not executed by the analysis pipeline.**

---

## 🔍 What CiphR Does

CiphR follows an APK from ingestion to campaign-level intelligence:

```text
                         Android APK
                             │
                             ▼
                  ┌─────────────────────┐
                  │ Upload & Validation │
                  │ SHA-256 / ZIP Check │
                  └──────────┬──────────┘
                             │
                             ▼
                  ┌─────────────────────┐
                  │   Static Analysis   │
                  │      Androguard      │
                  └──────────┬──────────┘
                             │
            ┌────────────────┼────────────────┐
            ▼                ▼                ▼
     ┌─────────────┐  ┌──────────────┐  ┌──────────────┐
     │ Manifest &  │  │ DEX Static   │  │ Certificate  │
     │ Components  │  │ Intelligence │  │ Analysis     │
     └──────┬──────┘  └──────┬───────┘  └──────┬───────┘
            │                │                 │
            └────────────────┼─────────────────┘
                             ▼
                  ┌─────────────────────┐
                  │ Risk & MITRE Engine │
                  │ Evidence + Findings │
                  └──────────┬──────────┘
                             │
                             ▼
                  ┌─────────────────────┐
                  │ Correlation Engine  │
                  │ Certificate / TLSH  │
                  │ Shared Indicators   │
                  └──────────┬──────────┘
                             │
                             ▼
                  ┌─────────────────────┐
                  │ Campaign Formation  │
                  │ + Relationship Graph│
                  └──────────┬──────────┘
                             │
                             ▼
                  ┌─────────────────────┐
                  │ Threat Narrative &  │
                  │ Analyst Dashboard   │
                  └─────────────────────┘
```

---

## ✨ Core Capabilities

### 🔐 Secure APK Ingestion

* `.apk` validation
* ZIP integrity validation
* Path-traversal protection
* File-size limits
* SHA-256 identification
* Duplicate upload detection
* Safe handling of untrusted APK input
* Malformed APK handling
* Streaming upload processing

### 📱 Android Static Analysis

CiphR uses **Androguard** to extract real Android application metadata, including:

* Package name
* Application name
* Version information
* Minimum and target SDK
* Permissions
* Activities
* Services
* Broadcast receivers
* Content providers
* Signing certificate information

### ⚖️ Deterministic Risk Scoring

CiphR uses explainable heuristic rules to produce risk assessments.

Each recognized indicator can contribute an explicit weight and corresponding evidence.

The system maintains the relationship:

```text
Indicator
    ↓
Evidence
    ↓
Risk Weight
    ↓
Risk Contribution
```

The final risk score is bounded to a maximum of `100`.

This allows an analyst to understand:

> **Why did this APK receive this risk score?**

---

## 🎯 MITRE ATT&CK for Mobile

Detected application behaviors are mapped to relevant **MITRE ATT&CK for Mobile** techniques.

Depending on the evidence present, CiphR can identify behaviors associated with areas such as:

* Accessibility abuse
* SMS-related abuse
* Device administrator capabilities
* Location access
* Contact access
* Camera/audio access
* Boot persistence
* System alert window abuse
* Other evidence-supported Android behaviors

MITRE mappings are treated as **evidence-backed classifications**, rather than simply attaching generic technique labels.

---

## 🧬 DEX Static Intelligence

CiphR performs static analysis of extracted DEX bytecode.

The DEX analyzer can identify:

* Suspicious Android API signatures
* `Runtime.exec`
* Dynamic class-loading APIs
* Reflection-related APIs
* Hardcoded IPv4 addresses
* URLs
* Domains
* Base64-encoded payload indicators
* Command-related strings
* Static behavioral co-occurrence patterns

### Behavioral Heuristics

For example:

```text
Runtime.exec
      +
Command-related content
      ↓
PROCESS_EXECUTION_WITH_COMMAND_CONTENT
```

and:

```text
Dynamic Loading API
      +
Network / Encoded Payload Indicator
      ↓
DYNAMIC_LOADING_WITH_PAYLOAD_INDICATOR
```

These findings are intentionally conservative.

> **Important:** DEX behavioral findings represent static evidence and co-occurrence. They do not prove that an APK actually executed a command, downloaded code, or performed dynamic loading at runtime.

---

## 🔏 Certificate & Similarity Intelligence

CiphR extracts signing certificate information and uses certificate relationships as one signal for correlating APK samples.

It also supports **TLSH fuzzy similarity** when the required runtime/native dependencies are available.

This enables relationships such as:

```text
APK A
 │
 ├── Same signing certificate ──► APK B
 │
 └── High fuzzy similarity ─────► APK C
```

TLSH availability is environment-dependent. When the required capability is unavailable, CiphR reports that state rather than fabricating a similarity result.

---

## 🔗 Campaign Correlation

CiphR does not treat APKs as isolated files.

Samples can be correlated using multiple signals, including:

* Identical signing certificates
* TLSH similarity
* Shared high-risk indicators

Relationships retain information such as:

* Relationship type
* Confidence
* Supporting evidence
* Campaign association

A simplified campaign relationship can look like:

```text
                       Campaign
                           │
              ┌────────────┼────────────┐
              │            │            │
              ▼            ▼            ▼
            APK A        APK B        APK C
              │            │            │
          Certificate     TLSH       Shared
             Match       Match      Indicator
```

CiphR can expose graph-ready campaign data for investigation and visualization.

---

## 🖥️ Analyst Dashboard

The frontend is built with **React** and **Vite** and provides an analyst-oriented interface for investigating APK intelligence.

The dashboard includes workflows for:

* APK upload
* Analysis status
* APK analysis
* Threat reports
* Campaign investigation
* Relationship graphs
* Search
* Analytics
* Alerts
* Analysis history
* Settings
* Report export

The intended workflow is:

```text
Upload APK
    ↓
Analysis Pipeline
    ↓
Threat Overview
    ↓
Detailed Findings
    ↓
Threat Report
    ↓
Related Samples
    ↓
Campaign Investigation
```

---

## 🤖 LLM Threat Narratives

CiphR supports an LLM provider abstraction for generating analyst-oriented threat narratives.

Supported integrations include:

* **Groq**
* **Google Gemini**
* **Mock Provider**

The LLM operates on structured analysis evidence rather than being treated as the source of truth.

APK-derived content is considered **untrusted input**, helping protect the narrative-generation pipeline against malicious strings and prompt-injection-style content originating from analyzed applications.

When external LLM credentials are unavailable, the configured fallback provider can be used for development and testing.

---

## 🧠 EMBER2024 Evidence Provider

CiphR also contains an EMBER2024-based machine-learning evidence provider.

EMBER is treated as an **additional evidence source** rather than replacing deterministic static analysis.

The architecture allows multiple sources of evidence to contribute independently:

```text
Static Analysis
       +
DEX Intelligence
       +
Certificate / Similarity
       +
EMBER Evidence
       +
Threat Intelligence
       ↓
Evidence Fusion
       ↓
Analyst Intelligence
       ↓
LLM Narrative
```

The LLM does not determine the underlying evidence.

---

## 🏗️ Backend Architecture

The backend is organized around a FastAPI service layer:

```text
backend/
├── app/
│   ├── api/
│   │   └── routes/
│   ├── core/
│   ├── db/
│   ├── ember/
│   ├── fusion/
│   ├── integrations/
│   │   └── llm/
│   ├── schemas/
│   └── services/
│       ├── apk_analysis_service.py
│       ├── certificate_service.py
│       ├── correlation_service.py
│       ├── dex_analysis_service.py
│       ├── pipeline_service.py
│       ├── tlsh_service.py
│       └── upload_service.py
├── alembic/
├── benchmarks/
├── scripts/
├── tests/
├── API_CONTRACT.md
├── IMPLEMENTATION_STATUS_REPORT.md
├── INTEGRATION_NOTES.md
└── requirements.txt
```

---

## 🌐 API

The backend exposes its REST API under:

```text
/api/v1
```

Development base URL:

```text
http://localhost:8000/api/v1
```

### Health

```http
GET /api/v1/health
```

### Samples

```http
POST /api/v1/samples/upload
GET  /api/v1/samples
GET  /api/v1/samples/{sample_id}
GET  /api/v1/samples/{sample_id}/status
GET  /api/v1/samples/{sample_id}/analysis
GET  /api/v1/samples/{sample_id}/findings
GET  /api/v1/samples/{sample_id}/related
```

### Campaigns

```http
GET /api/v1/campaigns
GET /api/v1/campaigns/{campaign_id}
GET /api/v1/campaigns/{campaign_id}/samples
GET /api/v1/campaigns/{campaign_id}/graph
```

For the complete API contract, see:

[`backend/API_CONTRACT.md`](backend/API_CONTRACT.md)

---

## 🛠️ Technology Stack

### Backend

| Component           | Technology           |
| ------------------- | -------------------- |
| API                 | FastAPI              |
| Language            | Python               |
| ORM                 | SQLAlchemy           |
| Migrations          | Alembic              |
| APK Analysis        | Androguard           |
| Async Database      | asyncpg / aiosqlite  |
| File Identification | SHA-256              |
| Fuzzy Similarity    | TLSH                 |
| ML Evidence         | EMBER2024 / LightGBM |
| LLM                 | Groq / Google Gemini |
| Validation          | Pydantic             |
| Testing             | Pytest               |

### Frontend

| Component           | Technology                     |
| ------------------- | ------------------------------ |
| UI                  | React                          |
| Build Tool          | Vite                           |
| Routing             | React Router                   |
| Charts              | Recharts                       |
| Graph Visualization | vis-network / 3D graph tooling |
| Icons               | Lucide React                   |
| PDF Reports         | jsPDF                          |

---

## 🚀 Getting Started

### 1. Clone the Repository

```bash
git clone https://github.com/skg2k05/CiphR.git
cd CiphR
```

---

### 2. Start the Backend

```bash
cd backend
```

Create a virtual environment:

```bash
python -m venv .venv
```

Activate it on Windows:

```powershell
.\.venv\Scripts\Activate.ps1
```

Install dependencies:

```bash
pip install -r requirements.txt
```

Create the environment file:

```powershell
Copy-Item .env.example .env
```

Configure the required environment variables.

Start the API:

```bash
uvicorn app.main:app --reload
```

The API will normally be available at:

```text
http://localhost:8000
```

---

### 3. Start the Frontend

Open another terminal:

```bash
cd frontend
npm install
npm run dev
```

Vite will display the local development URL, normally:

```text
http://localhost:5173
```

---

## 🧪 Testing

Backend tests are located in:

```text
backend/tests/
```

Run the backend test suite:

```bash
cd backend
python -m pytest tests -v
```

The test suite covers areas including:

* APK analysis
* Authentication
* DEX analysis
* EMBER integration
* Evidence fusion
* Hardening
* LLM providers
* MITRE mappings
* Multi-APK processing
* Risk scoring
* Security regression
* Campaign/shadow integration
* TLSH

Some test workflows generate temporary APK fixtures under:

```text
backend/tests/fixtures/demo_dataset/
```

These generated fixtures are reproducible and are not required to be committed to the repository.

---

## 🔒 Security Model

CiphR treats uploaded APKs as potentially malicious inputs.

The backend includes protections covering areas such as:

* Malformed APK handling
* ZIP/path traversal
* Excessive file sizes
* Duplicate uploads
* Invalid identifiers
* Resource-heavy extracted content
* Untrusted LLM input
* Database parameterization
* Pipeline failure handling

Most importantly:

> **Uploaded APKs are not executed as part of CiphR's static-analysis pipeline.**

The platform extracts and analyzes application artifacts instead.

---

## 📌 Current Scope

CiphR currently provides:

* Secure APK ingestion
* Manifest/component extraction
* Deterministic permission and indicator scoring
* MITRE ATT&CK for Mobile mapping
* Certificate analysis
* DEX static intelligence
* DEX behavioral heuristics
* TLSH similarity support
* Multi-sample correlation
* Campaign generation
* Campaign relationship graphs
* Threat-intelligence integration
* EMBER2024 evidence
* LLM-assisted threat narratives
* Analyst dashboard
* API integration
* Automated regression and security testing

---

## ⚠️ Limitations

CiphR intentionally does **not** claim to provide:

* Dynamic APK execution
* Full malware sandboxing
* Runtime behavioral telemetry
* Complete DEX control-flow analysis
* Complete DEX data-flow analysis
* Dynamic code tracing
* Guaranteed malware classification

DEX behavioral findings are static indicators and should be interpreted as supporting evidence rather than proof of runtime behavior.

TLSH functionality depends on the runtime environment and required native dependencies.

Real external LLM inference requires the relevant provider credentials. Development and testing can use the configured fallback provider.

---

## 📚 Documentation

Additional technical documentation is available in the repository:

* [`backend/API_CONTRACT.md`](backend/API_CONTRACT.md) — REST API contract
* [`backend/IMPLEMENTATION_STATUS_REPORT.md`](backend/IMPLEMENTATION_STATUS_REPORT.md) — implementation and architecture documentation
* [`backend/INTEGRATION_NOTES.md`](backend/INTEGRATION_NOTES.md) — integration and setup notes

---

## 💡 Project Philosophy

CiphR is built around a simple principle:

> **Evidence first. Explanation second.**

The system should help an analyst determine:

1. **What was observed**
2. **Where it was observed**
3. **Why it matters**
4. **Which technique it may represent**
5. **How strongly it contributed to the risk assessment**
6. **Which other APKs may be related**
7. **What should be investigated next**

The goal is to move beyond isolated APK scanning toward structured **fraud intelligence and campaign investigation**.

---

## 👥 Team

CiphR was developed collaboratively by a four-member team.

| Team Member         | GitHub                                                 |
| ------------------- | ------------------------------------------------------ |
| **Sushil Kumar Gauda** | [@skg2k05](https://github.com/skg2k05)                 |
| **Saloni Kumari**   | [@saloni1225](https://github.com/saloni1225) |
| **Priyanshi Mohanty**   | [@Priyanshi305](https://github.com/Priyanshi305) |
| **Anup Kumar Jena**   | [@AKJenaX](https://github.com/AKJenaX) |

---

## 📊 Project Status

**Functional MVP / Research & Demonstration Platform**

The `main` branch contains the integrated CiphR platform, including the backend intelligence pipeline, DEX static intelligence, campaign correlation, threat-intelligence capabilities, EMBER evidence integration, LLM narrative infrastructure, and React analyst dashboard.

CiphR is currently suitable for:

* Security research
* Android malware/fraud analysis
* APK triage
* Threat-intelligence demonstrations
* Campaign correlation experiments
* Academic projects
* Security engineering demonstrations

---

## 📄 License

Add the project's chosen license here before public distribution.

---

## 🔗 Repository

**GitHub:**
https://github.com/skg2k05/CiphR
