import json
import logging
import os

import anthropic

logger = logging.getLogger(__name__)

# The model can be changed without touching the code, e.g. AI_MODEL=claude-sonnet-5-5
MODEL = os.getenv("AI_MODEL", "claude-haiku-5-5")


async def analyze_deployment(deployment_data: dict) -> dict:
    """Returns risk analysis. Falls back to rule-based analysis if AI is unavailable."""
    api_key = os.getenv("ANTHROPIC_API_KEY")

    if not api_key:
        # No API key: use rule-based analysis
        return _mock_analysis(deployment_data)

    try:
        return _ai_analysis(deployment_data, api_key)
    except Exception as e:
        # API error, timeout or invalid JSON: fall back instead of failing
        logger.warning("AI analysis failed, using rule-based fallback: %s", e)
        return _mock_analysis(deployment_data)


def _ai_analysis(deployment_data: dict, api_key: str) -> dict:
    client = anthropic.Anthropic(api_key=api_key)

    prompt = f"""
    You are a DevOps risk assessment AI. Analyze this deployment and respond in JSON only.
    
    Deployment details:
    - Service: {deployment_data['service_name']}
    - Image tag: {deployment_data['image_tag']}
    - Environment: {deployment_data['environment']}
    - Replicas: {deployment_data['replicas']}
    - Previous incidents: {deployment_data['previous_incidents']}
    
    Respond with exactly this JSON structure, nothing else:
    {{
        "risk_level": "LOW|MEDIUM|HIGH",
        "risk_score": <0-100>,
        "reasoning": "<one sentence>",
        "recommendations": ["<action1>", "<action2>"]
    }}
    """

    message = client.messages.create(
        model=MODEL,
        max_tokens=500,
        messages=[{"role": "user", "content": prompt}]
    )

    parsed = json.loads(message.content[0].text)
    parsed["mock_mode"] = False
    return parsed

def _mock_analysis(deployment_data: dict) -> dict:
    """Rule-based risk analysis when AI is unavailable"""
    risk_score = 0
    reasons = []
    recommendations = []
    
    if deployment_data["environment"] == "production":
        risk_score += 40
        reasons.append("Production deployment")
        recommendations.append("Ensure rollback plan is ready")
    
    if deployment_data["previous_incidents"] > 0:
        risk_score += deployment_data["previous_incidents"] * 15
        reasons.append(f"{deployment_data['previous_incidents']} previous incidents")
        recommendations.append("Review incident history before deploying")
    
    if deployment_data["replicas"] < 2:
        risk_score += 20
        reasons.append("Single replica - no redundancy")
        recommendations.append("Increase replicas to at least 2 for resilience")
    
    if "latest" in deployment_data["image_tag"]:
        risk_score += 25
        reasons.append("Using 'latest' tag is unpredictable")
        recommendations.append("Pin to specific image digest instead of 'latest'")
    
    risk_score = min(risk_score, 100)
    
    if risk_score < 30:
        risk_level = "LOW"
    elif risk_score < 60:
        risk_level = "MEDIUM"
    else:
        risk_level = "HIGH"
    
    if not recommendations:
        recommendations.append("No immediate action required")
    
    return {
        "risk_level": risk_level,
        "risk_score": risk_score,
        "reasoning": " | ".join(reasons) if reasons else "Standard deployment, no risk factors detected",
        "recommendations": recommendations,
        "mock_mode": True
    }
