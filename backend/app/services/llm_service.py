from app.core.config import settings
from app.integrations.llm.base import LLMProvider
from app.integrations.llm.mock_provider import MockLLMProvider
from app.integrations.llm.groq_provider import GroqProvider
from app.integrations.llm.gemini_provider import GeminiProvider

def get_llm_provider() -> LLMProvider:
    """Factory to return the configured LLM provider."""
    # Use real Groq API if key is present
    if settings.GROQ_API_KEY:
        return GroqProvider(api_key=settings.GROQ_API_KEY)
        
    # Fallback to Gemini if added in the future
    if settings.GEMINI_API_KEY:
        return GeminiProvider(api_key=settings.GEMINI_API_KEY)
        
    # Fallback to mock if no keys are missing
    return MockLLMProvider()

async def generate_narrative(analysis_data: dict, findings: list) -> str:
    provider = get_llm_provider()
    return await provider.generate_threat_narrative(analysis_data, findings)
