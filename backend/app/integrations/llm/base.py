from abc import ABC, abstractmethod
from typing import List, Dict, Any

class LLMProvider(ABC):
    @abstractmethod
    async def generate_threat_narrative(self, analysis_data: Dict[str, Any], findings: List[Dict[str, Any]]) -> str:
        """Generates a plain-English threat narrative based on structured analysis evidence."""
        pass
