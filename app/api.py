"""API REST para el detector de phishing."""

from fastapi import FastAPI, File, UploadFile, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from typing import List, Optional
import base64
import json

from app.agent.multimodal_phishing_agent import MultimodalPhishingAgent
from app.tools.multimodal_analyzer import MultimodalAnalyzer

app = FastAPI(
    title="Phishing Detector API",
    description="API para detección de phishing usando análisis multimodal",
    version="1.0.0"
)

# Configurar CORS
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Modelos de datos
class EmailRequest(BaseModel):
    text: str
    images: Optional[List[str]] = []

class AnalysisResponse(BaseModel):
    classification: str
    confidence: float
    risk_level: str
    text_analysis: dict
    image_analysis: dict
    domain_analysis: dict
    recommendation: str
    language: str

# Instanciar agentes
phishing_agent = MultimodalPhishingAgent()
multimodal_analyzer = MultimodalAnalyzer()

@app.post("/analyze/", response_model=AnalysisResponse)
async def analyze_email(request: EmailRequest):
    """Analiza un email para detectar phishing."""
    try:
        # Preparar contenido
        content = await multimodal_analyzer.prepare_content(
            text=request.text,
            images=request.images or []
        )
        
        # Analizar con el agente
        result = await phishing_agent.analyze_email(
            request.text,
            request.images or []
        )
        
        return AnalysisResponse(
            classification=result["classification"],
            confidence=result["confidence"],
            risk_level=result["risk_level"],
            text_analysis=result["text_analysis"],
            image_analysis=result["image_analysis"],
            domain_analysis=result["domain_analysis"],
            recommendation=result["recommendation"],
            language=content["text"]["language"]
        )
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.post("/analyze/file/")
async def analyze_email_file(file: UploadFile = File(...)):
    """Analiza un archivo de email."""
    try:
        content = await file.read()
        text = content.decode()
        
        # Extraer imágenes si las hay
        images = []
        # TODO: Implementar extracción de imágenes del archivo
        
        return await analyze_email(EmailRequest(text=text, images=images))
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/health")
async def health_check():
    """Endpoint de health check."""
    return {"status": "healthy", "version": "1.0.0"} 