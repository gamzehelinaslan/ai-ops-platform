import pytest
from app.analyzer import analyze_deployment

@pytest.mark.asyncio
async def test_mock_high_risk():
    """Production + latest tag + incidents = HIGH risk expectation"""
    result = await analyze_deployment({
        "service_name": "payment-service",
        "image_tag": "latest",
        "environment": "production",
        "replicas": 1,
        "previous_incidents": 3
    })
    assert result["mock_mode"] == True
    assert result["risk_level"] == "HIGH"
    assert result["risk_score"] > 60

@pytest.mark.asyncio
async def test_mock_low_risk():
    """Staging + specific tag + no incidents = LOW risk expectation"""
    result = await analyze_deployment({
        "service_name": "frontend",
        "image_tag": "v1.2.3",
        "environment": "staging",
        "replicas": 2,
        "previous_incidents": 0
    })
    assert result["mock_mode"] == True
    assert result["risk_level"] == "LOW"
