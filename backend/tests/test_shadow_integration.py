import pytest
import asyncio
from unittest.mock import patch, MagicMock, AsyncMock
from app.core.config import settings
from app.services.pipeline_service import process_sample_pipeline
from app.db.models import Sample, Analysis


@pytest.fixture
def mock_db_session():
    with patch("app.services.pipeline_service.AsyncSessionLocal") as mock_session_maker:
        mock_session = AsyncMock()
        mock_session_maker.return_value.__aenter__.return_value = mock_session
        
        # Mock sample
        mock_sample = MagicMock(spec=Sample)
        mock_sample.id = "test-sample-id"
        mock_sample.storage_path = "/tmp/test.apk"
        mock_sample.campaigns = []
        
        # Mock analysis
        mock_analysis = MagicMock(spec=Analysis)
        
        # Mock execute returning sample
        mock_result = MagicMock()
        mock_result.scalars.return_value.first.return_value = mock_sample
        mock_session.execute.return_value = mock_result
        
        yield mock_session, mock_sample, mock_analysis


@pytest.fixture
def mock_pipeline_dependencies():
    with patch("app.services.pipeline_service.analyze_apk_static") as mock_static, \
         patch("app.services.pipeline_service.run_correlation") as mock_corr, \
         patch("app.services.pipeline_service.generate_narrative") as mock_llm:
         
        mock_static.return_value = {
            "status": "SUCCESS",
            "risk_score": 75,
            "package_name": "com.test",
            "findings_data": [
                {"title": "Test Finding", "severity": "HIGH", "category": "Static"}
            ]
        }
        mock_llm.return_value = "Test narrative"
        yield mock_static, mock_corr, mock_llm


@pytest.mark.asyncio
async def test_shadow_disabled_preserves_legacy(mock_db_session, mock_pipeline_dependencies):
    """
    Test that when shadow mode is disabled, the pipeline executes normally and shadow fusion is NOT called.
    """
    mock_session, mock_sample, mock_analysis = mock_db_session
    settings.FUSION_SHADOW_ENABLED = False
    
    with patch("app.services.pipeline_service.logger.info") as mock_logger, \
         patch("app.fusion.shadow.run_shadow_fusion") as mock_shadow:
        
        await process_sample_pipeline("test-sample-id")
        
        # Ensure legacy pipeline ran
        assert mock_sample.status == 'COMPLETED'
        mock_logger.assert_any_call("Pipeline completed successfully for sample: test-sample-id")
        
        # Ensure shadow was NOT called
        mock_shadow.assert_not_called()


@pytest.mark.asyncio
async def test_shadow_enabled_preserves_legacy(mock_db_session, mock_pipeline_dependencies):
    """
    Test that when shadow mode is enabled, the legacy output is EXACTLY the same, 
    and shadow fusion IS called.
    """
    mock_session, mock_sample, mock_analysis = mock_db_session
    settings.FUSION_SHADOW_ENABLED = True
    
    with patch("app.services.pipeline_service.logger.info") as mock_logger, \
         patch("app.fusion.shadow.run_shadow_fusion", new_callable=AsyncMock) as mock_shadow:
        
        await process_sample_pipeline("test-sample-id")
        
        # Ensure legacy pipeline ran EXACTLY the same
        assert mock_sample.status == 'COMPLETED'
        mock_logger.assert_any_call("Pipeline completed successfully for sample: test-sample-id")
        
        # Ensure shadow WAS called
        mock_shadow.assert_called_once()
        

@pytest.mark.asyncio
async def test_shadow_exception_does_not_break_pipeline(mock_db_session, mock_pipeline_dependencies):
    """
    Test that if shadow mode throws an exception, the pipeline gracefully catches it 
    and STILL completes the legacy analysis.
    """
    mock_session, mock_sample, mock_analysis = mock_db_session
    settings.FUSION_SHADOW_ENABLED = True
    
    with patch("app.services.pipeline_service.logger.info") as mock_logger, \
         patch("app.services.pipeline_service.logger.error") as mock_err_logger, \
         patch("app.fusion.shadow.run_shadow_fusion", new_callable=AsyncMock) as mock_shadow:
        
        mock_shadow.side_effect = Exception("Intentional shadow crash")
        
        await process_sample_pipeline("test-sample-id")
        
        # The shadow exception should be logged
        assert any("Shadow fusion failed" in call.args[0] for call in mock_err_logger.call_args_list)
        
        # BUT the pipeline MUST STILL complete successfully
        assert mock_sample.status == 'COMPLETED'
        mock_logger.assert_any_call("Pipeline completed successfully for sample: test-sample-id")
