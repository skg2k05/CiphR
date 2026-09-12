from app.core.config import settings
from app.integrations.llm.base import LLMProvider
from app.integrations.llm.mock_provider import MockLLMProvider
# In a full implementation, you would import GroqProvider or GeminiProvider here.
# from app.integrations.llm.groq_provider import GroqProvider

def get_llm_provider() -> LLMProvider:
    """Factory to return the configured LLM provider."""
    # MVP: Fallback to mock if keys are missing
    if settings.GROQ_API_KEY:
        # return GroqProvider(api_key=settings.GROQ_API_KEY)
        pass # Placeholder for Groq
    if settings.GEMINI_API_KEY:
        # return GeminiProvider(api_key=settings.GEMINI_API_KEY)
        pass # Placeholder for Gemini
        
    return MockLLMProvider()

async def generate_narrative(analysis_data: dict, findings: list) -> str:
    provider = get_llm_provider()
    return await provider.generate_threat_narrative(analysis_data, findings)
