from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
from dotenv import load_dotenv
import os
from app.analyzer import analyze_deployment

load_dotenv()

app = FastAPI(
    title="AI Ops Platform",
    description="AI-powered deployment risk analyzer",
    version="1.0.0"
)

class DeploymentRequest(BaseModel):
    service_name: str
    image_tag: str
    environment: str  # staging, production
    replicas: int = 1
    previous_incidents: int = 0

class AnalysisResponse(BaseModel):
    risk_level: str      # LOW, MEDIUM, HIGH
    risk_score: int      # 0-100
    reasoning: str
    recommendations: list[str]
    mock_mode: bool      # API key yoksa True

@app.get("/health")
def health_check():
    """Load balancer and k8s check this endpoint"""
    return {
        "status": "healthy",
        "version": "1.0.0",
        "ai_enabled": bool(os.getenv("ANTHROPIC_API_KEY"))
    }

@app.post("/analyze-deployment", response_model=AnalysisResponse)
async def analyze(request: DeploymentRequest):
    """Risk analysis with AI via deployment info. If no AI key use mock response"""
    try:
        result = await analyze_deployment(request.dict())
        return result
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/")
def root():
    return {"message": "AI Ops Platform - see /docs for API documentation"}
