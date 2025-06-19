"""Analizador multimodal mejorado con optimización y soporte multiidioma."""

import logging
from typing import Dict, List, Optional, Tuple

from app.utils.image_optimizer import ImageOptimizer
from app.utils.language_support import LanguageManager

logger = logging.getLogger(__name__)

class MultimodalAnalyzer:
    """Analizador multimodal con optimización y soporte multiidioma."""
    
    def __init__(self, config: Optional[Dict] = None):
        self.config = config or {}
        self.image_optimizer = ImageOptimizer(config)
        self.language_manager = LanguageManager()
    
    async def prepare_content(self, text: str, images: List[str]) -> Dict:
        """Prepara contenido para análisis multimodal.
        
        Args:
            text: Texto del email
            images: Lista de imágenes en base64
            
        Returns:
            Dict con contenido preparado y metadatos
        """
        try:
            # Detectar idioma
            language = self.language_manager.detect_language(text)
            
            # Analizar patrones de texto
            text_analysis = self.language_manager.analyze_text(text, language)
            
            # Optimizar imágenes
            optimized_images = []
            image_metadata = []
            
            for img_b64 in images:
                opt_img, meta = self.image_optimizer.optimize_base64(img_b64)
                optimized_images.append(opt_img)
                image_metadata.append(meta)
            
            return {
                "text": {
                    "content": text,
                    "language": language,
                    "analysis": text_analysis
                },
                "images": {
                    "content": optimized_images,
                    "metadata": image_metadata,
                    "count": len(optimized_images)
                }
            }
            
        except Exception as e:
            logger.error(f"Error preparando contenido: {e}")
            raise
    
    def format_llm_prompt(self, content: Dict) -> str:
        """Formatea el prompt para el LLM basado en el idioma detectado."""
        language = content["text"]["language"]
        
        # Prompts multiidioma
        prompts = {
            "es": """Analiza este email para detectar phishing:
                    - Texto del email: {text}
                    - Número de imágenes: {num_images}
                    - Patrones sospechosos detectados: {patterns}
                    
                    Analiza especialmente:
                    1. Legitimidad de logos/imágenes
                    2. Coherencia texto-imagen
                    3. Urgencia o amenazas
                    4. Solicitud de datos sensibles""",
                    
            "en": """Analyze this email for phishing:
                    - Email text: {text}
                    - Number of images: {num_images}
                    - Suspicious patterns detected: {patterns}
                    
                    Pay special attention to:
                    1. Logo/image legitimacy
                    2. Text-image coherence
                    3. Urgency or threats
                    4. Sensitive data requests""",
                    
            "fr": """Analysez cet email pour détecter le phishing:
                    - Texte de l'email: {text}
                    - Nombre d'images: {num_images}
                    - Motifs suspects détectés: {patterns}
                    
                    Analysez particulièrement:
                    1. Légitimité des logos/images
                    2. Cohérence texte-image
                    3. Urgence ou menaces
                    4. Demande de données sensibles"""
        }
        
        # Usar prompt en idioma detectado o inglés por defecto
        prompt_template = prompts.get(language, prompts["en"])
        
        # Formatear prompt con contenido
        return prompt_template.format(
            text=content["text"]["content"],
            num_images=content["images"]["count"],
            patterns=content["text"]["analysis"]["matches"]
        )
    
    async def analyze(self, text: str, images: List[str]) -> Dict:
        """Realiza análisis multimodal completo.
        
        Args:
            text: Texto del email
            images: Lista de imágenes en base64
            
        Returns:
            Dict con resultados del análisis
        """
        try:
            # Preparar contenido
            content = await self.prepare_content(text, images)
            
            # Generar prompt para LLM
            prompt = self.format_llm_prompt(content)
            
            # TODO: Llamar al LLM con el prompt
            # Por ahora retornamos el análisis de texto y metadatos
            return {
                "content_analysis": content,
                "prompt": prompt,
                "llm_ready": True
            }
            
        except Exception as e:
            logger.error(f"Error en análisis multimodal: {e}")
            return {
                "error": str(e),
                "llm_ready": False
            } 