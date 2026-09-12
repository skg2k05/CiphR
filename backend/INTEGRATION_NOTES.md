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
   *Note: If the UUID is malformed, this will immediately return a `404 Not Found` to prevent cascading database errors.*
4. If `stages.pipeline` == `COMPLETED`, stop polling. Fetch `/analysis` and `/findings`.
5. If `stages.pipeline` == `FAILED`, stop polling and display the `error` string.

## Architecture Notes
- **CORS**: The backend is configured to accept `allow_origins=["*"]`. You can safely fetch APIs from `http://localhost:3000` or `http://localhost:5173` without encountering CORS blocks.
- **TLSH Implementation**: TLSH hashing is now **REAL** via `python-tlsh`. Because it is a C-extension that requires GCC/MSVC, a `Dockerfile` and `docker-compose.yml` are provided. Run `docker-compose up --build` to run the backend natively in a Linux environment. If you run the backend on Windows without C++ tools, TLSH gracefully downgrades to `ERROR_TLSH_UNAVAILABLE` without breaking the pipeline.
- **LLM Threat Intelligence**: LLM threat narrative generation is now **REAL** and natively invokes the Groq API when `GROQ_API_KEY` is provided in the `.env` file. If the key is missing, or if the API suffers a timeout, the backend gracefully defaults to the local `MockLLMProvider` or a safe error response without failing the pipeline.
- **Database**: The current `.env.example` points to `sqlite+aiosqlite:///./test.db` to prevent heavy local friction. When connecting to Supabase in production, change `DATABASE_URL` to `postgresql+asyncpg://...`.

## Testing
To ensure the backend works locally:
```bash
pytest tests/
```
All components are highly decoupled, permitting rapid UI scaling against stable JSON structures.
