"""Agente multimodal mejorado con threat intelligence, análisis de attachments y búsqueda web."""

import os
import logging
import json
from typing import Dict, List, Optional, Any
from dotenv import load_dotenv
from openai import OpenAI

from app.tools.multimodal_analyzer import MultimodalAnalyzer
from app.data_sources.threat_intelligence import ThreatIntelligenceManager
from app.tools.attachment_analyzer import AttachmentAnalyzer
from app.tools.web_intelligence import WebIntelligenceSearcher
from app.tools.domain_verifier import DomainVerifier

load_dotenv()
logger = logging.getLogger(__name__)

class EnhancedMultimodalPhishingAgent:
    """Agente mejorado con capacidades de threat intelligence y análisis completo."""
    
    def __init__(self, config: Optional[Dict] = None):
        self.config = config or {}
        
        # Componentes principales
        self.multimodal_analyzer = MultimodalAnalyzer(config)
        self.threat_intel = ThreatIntelligenceManager(config.get('threat_intelligence', {}))
        self.attachment_analyzer = AttachmentAnalyzer(config.get('attachment_analysis', {}))
        self.web_searcher = WebIntelligenceSearcher(config.get('web_search', {}))
        self.domain_verifier = DomainVerifier(config)
        
        # Cliente OpenAI
        self.client = OpenAI(
            api_key=os.getenv("OPENAI_API_KEY"),
            base_url=os.getenv("OPENAI_API_BASE", "https://api.openai.com/v1")
        )
        self.model = os.getenv("MODEL_NAME", "gpt-4-vision-preview")
    
    async def analyze_email_comprehensive(
        self, 
        email_content: str, 
        images: Optional[List[str]] = None,
        perform_web_search: bool = True,
        check_threat_intel: bool = True
    ) -> Dict[str, Any]:
        """Análisis completo del email con todas las capacidades mejoradas."""
        
        analysis_result = {
            "email_analysis": {},
            "attachment_analysis": {},
            "threat_intelligence": {},
            "web_intelligence": {},
            "enhanced_classification": "unknown",
            "confidence": 0.0,
            "risk_level": "unknown",
            "recommendation": "",
            "analysis_timestamp": "",
            "sources_used": []
        }
        
        try:
            logger.info("Iniciando análisis completo del email...")
            
            # 1. Análisis multimodal básico (texto + imágenes)
            logger.info("Realizando análisis multimodal...")
            multimodal_result = await self._perform_multimodal_analysis(email_content, images or [])
            analysis_result["email_analysis"] = multimodal_result
            analysis_result["sources_used"].append("multimodal_llm")
            
            # 2. Análisis de attachments
            logger.info("Analizando attachments...")
            attachment_result = self.attachment_analyzer.analyze_email_attachments(email_content)
            analysis_result["attachment_analysis"] = attachment_result
            analysis_result["sources_used"].append("attachment_scanner")
            
            # 3. Verificación con threat intelligence
            if check_threat_intel:
                logger.info("Consultando threat intelligence...")
                threat_result = await self._check_threat_intelligence(email_content)
                analysis_result["threat_intelligence"] = threat_result
                analysis_result["sources_used"].append("threat_intelligence")
            
            # 4. Búsqueda web inteligente
            if perform_web_search:
                logger.info("Realizando búsqueda web inteligente...")
                web_result = await self._perform_web_intelligence(email_content)
                analysis_result["web_intelligence"] = web_result
                analysis_result["sources_used"].append("web_search")
            
            # 5. Combinar resultados y generar clasificación final
            logger.info("Combinando resultados...")
            final_classification = self._combine_analysis_results(analysis_result)
            analysis_result.update(final_classification)
            
            # 6. Generar recomendación final
            analysis_result["recommendation"] = self._generate_final_recommendation(analysis_result)
            
            logger.info(f"Análisis completado: {analysis_result['enhanced_classification']}")
            
        except Exception as e:
            logger.error(f"Error en análisis completo: {e}")
            analysis_result["error"] = str(e)
            analysis_result["enhanced_classification"] = "error"
        
        return analysis_result
    
    async def _perform_multimodal_analysis(self, text: str, images: List[str]) -> Dict[str, Any]:
        """Realiza el análisis multimodal básico."""
        try:
            # Preparar contenido
            content = await self.multimodal_analyzer.prepare_content(text, images)
            prompt = self.multimodal_analyzer.format_llm_prompt(content)
            
            # Crear mensajes para el LLM
            messages = [
                {
                    "role": "system",
                    "content": "Eres un experto en detección de phishing bancario. Analiza el contenido y responde SOLO con JSON válido."
                },
                {
                    "role": "user",
                    "content": [{"type": "text", "text": prompt}]
                }
            ]
            
            # Añadir imágenes si existen
            if content["images"]["content"]:
                for img in content["images"]["content"]:
                    messages[-1]["content"].append({
                        "type": "image_url",
                        "image_url": {"url": img}
                    })
            
            # Llamar al LLM
            response = self.client.chat.completions.create(
                model=self.model,
                messages=messages,
                max_tokens=1500,
                temperature=0.1
            )
            
            result = response.choices[0].message.content
            if not result:
                raise ValueError("Respuesta vacía del modelo")
            
            # Parsear JSON y añadir metadatos
            llm_analysis = json.loads(result)
            
            return {
                "llm_analysis": llm_analysis,
                "language": content["text"]["language"],
                "preprocessing": {
                    "text_analysis": content["text"]["analysis"],
                    "image_optimization": content["images"]["metadata"]
                },
                "model_used": self.model
            }
            
        except Exception as e:
            logger.error(f"Error en análisis multimodal: {e}")
            return {"error": str(e), "model_used": self.model}
    
    async def _check_threat_intelligence(self, email_content: str) -> Dict[str, Any]:
        """Verifica el email contra fuentes de threat intelligence."""
        threat_results = {
            "domains_checked": [],
            "malicious_domains_found": [],
            "threat_scores": {},
            "total_sources": 0
        }
        
        try:
            # Extraer dominios del email
            import re
            domain_pattern = r'https?://([^/\s]+)|www\.([^/\s]+)|([a-zA-Z0-9.-]+\.[a-zA-Z]{2,})'
            matches = re.findall(domain_pattern, email_content)
            
            domains = set()
            for match in matches:
                for group in match:
                    if group and '.' in group:
                        domain = group.lower().strip()
                        if domain:
                            domains.add(domain)
            
            # Verificar cada dominio
            for domain in domains:
                check_result = await self.threat_intel.check_domain(domain)
                threat_results["domains_checked"].append(domain)
                threat_results["threat_scores"][domain] = check_result
                
                if check_result.get("is_malicious"):
                    threat_results["malicious_domains_found"].append(domain)
            
            # Obtener estado de proveedores
            provider_status = self.threat_intel.get_provider_status()
            threat_results["total_sources"] = len(provider_status)
            threat_results["provider_status"] = provider_status
            
        except Exception as e:
            logger.error(f"Error en threat intelligence: {e}")
            threat_results["error"] = str(e)
        
        return threat_results
    
    async def _perform_web_intelligence(self, email_content: str) -> Dict[str, Any]:
        """Realiza búsqueda web inteligente."""
        web_results = {
            "domain_reputation": {},
            "content_intelligence": {},
            "search_performed": False
        }
        
        try:
            # Extraer dominio principal para búsqueda de reputación
            import re
            domain_match = re.search(r'https?://([^/\s]+)', email_content)
            if domain_match:
                main_domain = domain_match.group(1)
                web_results["domain_reputation"] = await self.web_searcher.search_domain_reputation(main_domain)
            
            # Búsqueda de inteligencia de contenido
            web_results["content_intelligence"] = await self.web_searcher.search_email_content_intelligence(email_content)
            web_results["search_performed"] = True
            
        except Exception as e:
            logger.error(f"Error en web intelligence: {e}")
            web_results["error"] = str(e)
        
        return web_results
    
    def _combine_analysis_results(self, analysis: Dict[str, Any]) -> Dict[str, Any]:
        """Combina todos los resultados para generar clasificación final."""
        # Inicializar scores
        threat_score = 0.0
        confidence_score = 0.0
        evidence_count = 0
        
        # Score del análisis multimodal (peso: 40%)
        email_analysis = analysis.get("email_analysis", {})
        if "llm_analysis" in email_analysis:
            llm_result = email_analysis["llm_analysis"]
            if llm_result.get("classification") == "phishing":
                threat_score += 0.4
                evidence_count += 1
            confidence_score += llm_result.get("confidence", 0.0) * 0.4
        
        # Score de attachments (peso: 25%)
        attachment_analysis = analysis.get("attachment_analysis", {})
        if attachment_analysis.get("has_dangerous"):
            threat_score += 0.25
            evidence_count += 1
        attachment_risk = attachment_analysis.get("risk_score", 0.0)
        confidence_score += attachment_risk * 0.25
        
        # Score de threat intelligence (peso: 20%)
        threat_intel = analysis.get("threat_intelligence", {})
        malicious_domains = threat_intel.get("malicious_domains_found", [])
        if malicious_domains:
            threat_score += 0.2
            evidence_count += 1
        threat_confidence = min(len(malicious_domains) * 0.3, 1.0)
        confidence_score += threat_confidence * 0.2
        
        # Score de web intelligence (peso: 15%)
        web_intel = analysis.get("web_intelligence", {})
        domain_rep = web_intel.get("domain_reputation", {})
        reputation_score = domain_rep.get("reputation_score", 0.0)
        if reputation_score > 0.5:
            threat_score += 0.15
            evidence_count += 1
        confidence_score += reputation_score * 0.15
        
        # Determinar clasificación final
        if threat_score >= 0.6:
            classification = "phishing"
            risk_level = "high"
        elif threat_score >= 0.3:
            classification = "suspicious"
            risk_level = "medium"
        else:
            classification = "legitimate"
            risk_level = "low"
        
        # Ajustar confianza basada en evidencia
        final_confidence = min(confidence_score + (evidence_count * 0.1), 1.0)
        
        return {
            "enhanced_classification": classification,
            "confidence": final_confidence,
            "risk_level": risk_level,
            "threat_score": threat_score,
            "evidence_count": evidence_count,
            "analysis_timestamp": "",
        }
    
    def _generate_final_recommendation(self, analysis: Dict[str, Any]) -> str:
        """Genera recomendación final basada en todos los análisis."""
        classification = analysis.get("enhanced_classification", "unknown")
        confidence = analysis.get("confidence", 0.0)
        
        recommendations = []
        
        if classification == "phishing":
            recommendations.append("🚨 PHISHING CONFIRMADO")
            recommendations.append("• NO hacer clic en ningún enlace")
            recommendations.append("• NO proporcionar información personal")
            recommendations.append("• Eliminar el email inmediatamente")
            
            # Detalles específicos
            if analysis.get("attachment_analysis", {}).get("has_dangerous"):
                recommendations.append("• ATTACHMENTS PELIGROSOS DETECTADOS - No abrir")
            
            if analysis.get("threat_intelligence", {}).get("malicious_domains_found"):
                recommendations.append("• Dominios maliciosos conocidos detectados")
            
        elif classification == "suspicious":
            recommendations.append("⚠️ EMAIL SOSPECHOSO")
            recommendations.append("• Verificar con el remitente por otro canal")
            recommendations.append("• No proporcionar información sensible")
            recommendations.append("• Revisar detalles del remitente cuidadosamente")
            
        else:
            recommendations.append("✅ Email aparenta ser legítimo")
            recommendations.append("• Sin embargo, mantener precaución general")
            recommendations.append("• Verificar URLs antes de hacer clic")
        
        recommendations.append(f"\n📊 Confianza del análisis: {confidence*100:.1f}%")
        recommendations.append(f"🔍 Fuentes consultadas: {len(analysis.get('sources_used', []))}")
        
        return "\n".join(recommendations)
    
    async def get_enhanced_report(
        self, 
        email_content: str, 
        images: Optional[List[str]] = None,
        include_web_search: bool = True,
        include_threat_intel: bool = True
    ) -> str:
        """Genera un reporte completo y legible."""
        
        # Realizar análisis completo
        analysis = await self.analyze_email_comprehensive(
            email_content, 
            images, 
            include_web_search, 
            include_threat_intel
        )
        
        # Generar reporte
        report = f"""
🛡️ ANÁLISIS COMPLETO DE PHISHING
{'='*50}

🎯 CLASIFICACIÓN FINAL: {analysis['enhanced_classification'].upper()}
📊 CONFIANZA: {analysis['confidence']*100:.1f}%
⚠️ NIVEL DE RIESGO: {analysis['risk_level'].upper()}
🔍 FUENTES CONSULTADAS: {', '.join(analysis['sources_used'])}

"""
        
        # Análisis multimodal
        email_analysis = analysis.get("email_analysis", {})
        if "llm_analysis" in email_analysis:
            llm_result = email_analysis["llm_analysis"]
            report += f"""📧 ANÁLISIS MULTIMODAL:
   • Clasificación LLM: {llm_result.get('classification', 'N/A')}
   • Idioma detectado: {email_analysis.get('language', 'N/A')}
   • Modelo usado: {email_analysis.get('model_used', 'N/A')}

"""
        
        # Análisis de attachments
        attachment_analysis = analysis.get("attachment_analysis", {})
        if attachment_analysis:
            report += self.attachment_analyzer.get_attachment_summary(attachment_analysis)
            report += "\n\n"
        
        # Threat Intelligence
        threat_intel = analysis.get("threat_intelligence", {})
        if threat_intel and not threat_intel.get("error"):
            report += f"""🔍 THREAT INTELLIGENCE:
   • Dominios verificados: {len(threat_intel.get('domains_checked', []))}
   • Dominios maliciosos: {len(threat_intel.get('malicious_domains_found', []))}
   • Fuentes consultadas: {threat_intel.get('total_sources', 0)}

"""
            if threat_intel.get("malicious_domains_found"):
                report += "⚠️ DOMINIOS MALICIOSOS DETECTADOS:\n"
                for domain in threat_intel["malicious_domains_found"]:
                    report += f"   • {domain}\n"
                report += "\n"
        
        # Web Intelligence
        web_intel = analysis.get("web_intelligence", {})
        if web_intel.get("search_performed"):
            domain_rep = web_intel.get("domain_reputation", {})
            content_intel = web_intel.get("content_intelligence", {})
            report += self.web_searcher.get_intelligence_summary(domain_rep, content_intel)
            report += "\n"
        
        # Recomendación final
        report += f"""💡 RECOMENDACIÓN FINAL:
{analysis['recommendation']}
"""
        
        return report 