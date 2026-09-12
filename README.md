# CiphR

CiphR is a Fraud Intelligence Layer for detecting and correlating malicious Android APKs.

This repository currently contains the backend implementation. The frontend is meant to be implemented later and can be placed in a separate `frontend` directory.

## Architecture

The backend is built using:
- **Python 3.10+**
- **FastAPI** for high-performance async REST APIs
- **SQLAlchemy + asyncpg** for PostgreSQL/Supabase database access
- **Alembic** for database migrations
- **Androguard** for static APK analysis
- **python-tlsh** (Mocked locally if build fails) for fuzzy hashing and similarity comparison
- **LLM Abstraction** for generating human-readable threat narratives (Groq/Gemini support)

### Pipeline Orchestration
When an APK is uploaded, a background pipeline is triggered:
1. File Validation (Size, Extension, ZIP structure)
2. SHA-256 Hashing & Deduplication
3. Static Analysis (Permissions, Component extraction)
4. Certificate Fingerprinting
5. TLSH Fuzzy Hashing
6. Correlation Engine (Links sample to matching campaigns based on Certificate or TLSH)
7. Threat Narrative Generation (using Mock LLM or real API keys)

## Setup & Installation

### 1. Python Virtual Environment
Navigate to the `backend/` directory and create a virtual environment:
```bash
cd backend
python -m venv .venv
# Activate on Windows:
.\.venv\Scripts\Activate.ps1
# Activate on Linux/macOS:
source .venv/bin/activate
```

### 2. Install Dependencies
```bash
pip install -r requirements.txt
```
*(Note: If `py-tlsh` fails to compile on Windows due to missing C++ tools, the system automatically falls back to a mocked TLSH hashing mechanism to keep the pipeline functional).*

### 3. Environment Variables
Copy `.env.example` to `.env`:
```bash
cp .env.example .env
```
Update values inside `.env`. If you want to use Supabase, change `DATABASE_URL` to your Supabase PostgreSQL connection string. 

### 4. Database Setup & Migrations
Initialize the SQLite test database (or PostgreSQL if configured):
```bash
alembic upgrade head
```

### 5. Running the API Locally
Start the FastAPI server:
```bash
uvicorn app.main:app --reload
```
The API will be available at: `http://localhost:8000/api/v1`

## API Endpoints

Once the server is running, you can explore the Interactive API Documentation at:
**[http://localhost:8000/docs](http://localhost:8000/docs)**

### Key Contracts for Frontend Integration

**Health**
- `GET /api/v1/health`

**Samples**
- `POST /api/v1/samples/upload` (multipart/form-data)
- `GET /api/v1/samples`
- `GET /api/v1/samples/{sample_id}`
- `GET /api/v1/samples/{sample_id}/status`
- `GET /api/v1/samples/{sample_id}/analysis`
- `GET /api/v1/samples/{sample_id}/findings`

**Campaigns**
- `GET /api/v1/campaigns`
- `GET /api/v1/campaigns/{campaign_id}`
- `GET /api/v1/campaigns/{campaign_id}/samples`
- `GET /api/v1/campaigns/{campaign_id}/graph`

The graph endpoint returns a robust `{nodes: [], edges: []}` structure designed to be fed directly into a library like `vis-network`.

## Testing
To run the automated tests locally:
```bash
pytest tests/
```

## Known Limitations
- The `python-tlsh` dependency requires C++ build tools on Windows. The backend gracefully handles its absence by mocking TLSH to ensure development and testing can proceed smoothly without it.
- Supabase is supported through standard Postgres connections, meaning developers do not need the specific Supabase Python SDK, which abstracts away complex vendor-locking.
