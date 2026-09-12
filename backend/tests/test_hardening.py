import pytest
import uuid
import asyncio
from fastapi.testclient import TestClient
from sqlalchemy.ext.asyncio import AsyncSession
from unittest.mock import patch, MagicMock

from app.main import app
from app.core.utils import validate_uuid
from app.services.dex_analysis_service import analyze_dex
from fastapi import HTTPException

client = TestClient(app, headers={"X-API-Key": "test_mock_key"})

def test_validate_uuid_success():
    valid_id = str(uuid.uuid4())
    assert validate_uuid(valid_id) is True

def test_validate_uuid_failure():
    with pytest.raises(HTTPException) as excinfo:
        validate_uuid("not-a-uuid", "TestResource")
    assert excinfo.value.status_code == 404
    assert "TestResource not found" in str(excinfo.value.detail)

def test_api_malformed_uuid_returns_404():
    """Verify that passing malformed UUIDs to routes returns graceful 404 instead of 500 DB errors."""
    response = client.get("/api/v1/samples/invalid-id")
    assert response.status_code == 404
    
    response = client.get("/api/v1/campaigns/invalid-id")
    assert response.status_code == 404

@patch('app.services.dex_analysis_service.DEX')
def test_dex_analysis_bounds(mock_dex_class):
    """Test that DEX analysis bounds large inputs and caps lists."""
    class MockStringItem:
        def __init__(self, s):
            self.s = s
        def decode(self, *args, **kwargs):
            return self.s
        def __str__(self):
            return self.s
            
    class MockMethod:
        def __init__(self, class_name, name):
            self.class_name = class_name
            self.name = name
        def get_class_name(self):
            return self.class_name
        def get_name(self):
            return self.name
            
    class MockDex:
        def get_strings(self):
            # Yield 250 IP addresses
            for i in range(250):
                yield MockStringItem(f"192.168.1.{i}")
                
            # Yield 250 URLs
            for i in range(250):
                yield MockStringItem(f"http://example.com/{i}")
                
            # Yield a very large string
            yield MockStringItem("A" * 15000)
            
        def get_methods(self):
            # Yield 250 suspicious APIs (must be unique to bypass duplicate check)
            for i in range(250):
                yield MockMethod("Ljava/lang/Runtime;", f"exec_{i}")
                
    mock_dex_class.return_value = MockDex()
    
    # Patch SUSPICIOUS_APIS so our fake methods match
    dummy_rule = {
        'methods': [f"exec_{i}" for i in range(250)],
        'reason': 'test',
        'mitre': 'T1234',
        'weight': 10
    }
    with patch('app.services.dex_analysis_service.SUSPICIOUS_APIS', {'java.lang.Runtime': dummy_rule}):
        def mock_dex_generator():
            yield b'dummy_dex_bytes'

        result = analyze_dex(mock_dex_generator())
    
    # Assert bounds are respected
    assert len(result["hardcoded_ips"]) == 200
    assert len(result["urls"]) == 200
    assert len(result["suspicious_apis"]) == 200
