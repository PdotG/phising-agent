"""Agente de detección de phishing con capacidades multimodales."""

import os
from typing import Dict, List, Optional, Any
import logging
import json
from dotenv import load_dotenv
from openai import OpenAI

from app.tools.multimodal_analyzer import MultimodalAnalyzer

load_dotenv()
logger = logging.getLogger(__name__)

class MultimodalPhishingAgent:
    """Agente que usa GPT-4V para análisis multimodal de phishing."""
    
    def __init__(self, config: Optional[Dict] = None):
        self.analyzer = MultimodalAnalyzer(config)
        self.client = OpenAI(
            api_key=os.getenv("OPENAI_API_KEY"),
            base_url=os.getenv("OPENAI_API_BASE", "https://api.openai.com/v1")
        )
        self.model = os.getenv("MODEL_NAME", "gpt-4-vision-preview")
    
    async def analyze_email(self, text: str, images: Optional[List[str]] = None) -> Dict[str, Any]:
        """Analiza un email usando capacidades multimodales.
        
        Args:
            text: Contenido del email
            images: Lista opcional de imágenes en base64
            
        Returns:
            Dict con el análisis completo
        """
        try:
            # Preparar contenido
            content = await self.analyzer.prepare_content(text, images or [])
            
            # Obtener prompt formateado
            prompt = self.analyzer.format_llm_prompt(content)
            
            # Preparar mensajes para el modelo
            messages = [
                {
                    "role": "system",
                    "content": "Eres un experto en detección de phishing bancario."
                },
                {
                    "role": "user",
                    "content": [
                        {"type": "text", "text": prompt}
                    ]
                }
            ]
            
            # Añadir imágenes si existen
            if content["images"]["content"]:
                for img in content["images"]["content"]:
                    messages[-1]["content"].append({
                        "type": "image_url",
                        "image_url": {"url": img}
                    })
            
            # Llamar al modelo
            response = self.client.chat.completions.create(
                model=self.model,
                messages=messages,
                max_tokens=1000
            )
            
            # Procesar respuesta
            result = response.choices[0].message.content
            if not result:
                raise ValueError("Respuesta vacía del modelo")
            
            # Convertir respuesta JSON a dict y combinar con metadatos
            final_result = {
                **json.loads(result),
                "language": content["text"]["language"],
                "preprocessing": {
                    "text_analysis": content["text"]["analysis"],
                    "image_optimization": content["images"]["metadata"]
                }
            }
            
            return final_result
            
        except Exception as e:
            logger.error(f"Error en análisis multimodal: {e}")
            return {
                "error": str(e),
                "classification": "error",
                "confidence": 0.0,
                "risk_level": "unknown"
            }
    
    async def analyze_email_simple(self, text: str, images: Optional[List[str]] = None) -> str:
        """Versión simplificada que solo retorna la clasificación."""
        result = await self.analyze_email(text, images)
        return result.get("classification", "error")

    async def get_detailed_report(self, text: str, images: Optional[List[str]] = None) -> str:
        """Genera un reporte detallado en formato legible."""
        result = await self.analyze_email(text, images)
        
        if "error" in result:
            return f"❌ Error en el análisis: {result['error']}"
        
        # Generar reporte legible
        report = f"""
🔍 ANÁLISIS MULTIMODAL DE PHISHING ({result['language'].upper()})
{'='*50}

🎯 CLASIFICACIÓN: {result['classification'].upper()}
📊 CONFIANZA: {result['confidence']*100:.1f}%
⚠️  NIVEL DE RIESGO: {result['risk_level'].upper()}

📧 ANÁLISIS DE TEXTO:
   • Patrones sospechosos: {result['text_analysis']['suspicious_patterns']}
   • Lenguaje urgente: {'✅' if result['text_analysis']['urgency_language'] else '❌'}
   • Solicita datos personales: {'✅' if result['text_analysis']['requests_personal_data'] else '❌'}
   • Errores ortográficos: {'✅' if result['text_analysis']['spelling_errors'] else '❌'}
"""
        
        if result['image_analysis']['images_analyzed'] > 0:
            report += f"""
🖼️ ANÁLISIS DE IMÁGENES:
   • Imágenes analizadas: {result['image_analysis']['images_analyzed']}
   • Logos sospechosos: {'✅' if result['image_analysis']['suspicious_logos'] else '❌'}
   • Problemas de calidad: {'✅' if result['image_analysis']['logo_quality_issues'] else '❌'}
   • Colores incorrectos: {'✅' if result['image_analysis']['color_mismatches'] else '❌'}
   • Detalles: {result['image_analysis']['details']}
"""

        report += f"""
🌐 ANÁLISIS DE DOMINIOS:
   • Dominios encontrados: {', '.join(result['domain_analysis']['domains_found'])}
   • Dominios oficiales: {', '.join(result['domain_analysis']['official_domains'])}
   • Dominios sospechosos: {', '.join(result['domain_analysis']['suspicious_domains'])}
   • Suplantación de dominio: {'✅' if result['domain_analysis']['domain_spoofing'] else '❌'}

💡 RECOMENDACIÓN:
{result['recommendation']}
"""
        return report


# Funciones de conveniencia para mantener compatibilidad
async def analyze_email_multimodal(email_content: str) -> Dict[str, Any]:
    """Función de conveniencia para análisis multimodal."""
    agent = MultimodalPhishingAgent()
    return await agent.analyze_email(email_content)


async def get_multimodal_report(email_content: str) -> str:
    """Función de conveniencia para obtener reporte legible."""
    agent = MultimodalPhishingAgent()
    return await agent.get_detailed_report(email_content) 