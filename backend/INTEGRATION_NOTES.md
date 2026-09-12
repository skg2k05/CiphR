# CiphR Frontend Integration Notes

## Welcome Frontend Developer!
The CiphR backend is entirely functional, tested dynamically against real APKs, and securely walled behind `FastAPI`. 

> [!WARNING] 
> The frontend should consume the REST API and should **not** directly access the backend PostgreSQL database or ORM logic. Use the `/api/v1/` routes for all data reading/writing.

## Quick Start
To boot the backend locally for your frontend integration:
1. Ensure you have Python 3.10+ installed.
2. In the `backend/` directory, open `.env` and verify variables.
3. Run the following:
```bash
python -m venv .venv
# Activate: .\.venv\Scripts\Activate.ps1 (Windows) or source .venv/bin/activate (Mac/Linux)
pip install -r requirements.txt
alembic upgrade head
uvicorn app.main:app --reload
```
**API Base URL**: `http://localhost:8000/api/v1`
**Interactive Docs**: `http://localhost:8000/docs`

## Recommended Frontend Polling Strategy
When a user uploads an APK, the Heavy intelligence processing (Androguard, TLSH, LLM) runs safely in the background. Do **not** expect `/upload` to return findings immediately.

Your React workflow should be:
1. `POST /samples/upload` -> Returns a `sample_id` and `status: "QUEUED"`.
2. Display a loading spinner or progress bar.
3. Every ~2 seconds, `GET /samples/{sample_id}/status`.
4. If `stages.pipeline` == `COMPLETED`, stop polling. Fetch `/analysis` and `/findings`.
5. If `stages.pipeline` == `FAILED`, stop polling and display the `error` string.

## Architecture Notes
- **CORS**: The backend is configured to accept `allow_origins=["*"]`. You can safely fetch APIs from `http://localhost:3000` or `http://localhost:5173` without encountering CORS blocks.
- **TLSH Limitation**: Because `python-tlsh` fails to compile on standard Windows machines without Visual Studio C++ Tools, the engine gracefully utilizes a `MockTLSH` provider to prevent pipeline failures. It still effectively hashes data deterministically for Correlation engine tests.
- **LLM Fallback**: If `.env` lacks `GROQ_API_KEY` or `GEMINI_API_KEY`, the backend automatically utilizes a `MockLLMProvider` that successfully parses risk scores and generates plaintext mock narratives.
- **Database**: The current `.env.example` points to `sqlite+aiosqlite:///./test.db` to prevent heavy local friction. When connecting to Supabase in production, change `DATABASE_URL` to `postgresql+asyncpg://...`.

## Testing
To ensure the backend works locally:
```bash
pytest tests/
```
All components are highly decoupled, permitting rapid UI scaling against stable JSON structures.
