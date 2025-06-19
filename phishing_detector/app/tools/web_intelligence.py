"""Módulo de búsqueda web inteligente para verificar antecedentes de phishing."""

import asyncio
import aiohttp
import logging
import json
import re
from typing import Dict, List, Optional, Any
from datetime import datetime
import urllib.parse

logger = logging.getLogger(__name__)

class WebIntelligenceSearcher:
    """Buscador web inteligente para verificar antecedentes de phishing."""
    
    def __init__(self, config: Optional[Dict] = None):
        self.config = config or {}
        self.brave_api_key = self.config.get('brave_api_key')
        self.max_results = self.config.get('max_search_results', 5)
        self.search_engines = self._setup_search_engines()
    
    def _setup_search_engines(self) -> Dict[str, Dict]:
        """Configura los motores de búsqueda disponibles."""
        engines = {}
        
        # Brave Search (recomendado - privacidad)
        if self.brave_api_key:
            engines['brave'] = {
                'url': 'https://api.search.brave.com/res/v1/web/search',
                'headers': {
                    'Accept': 'application/json',
                    'Accept-Encoding': 'gzip',
                    'X-Subscription-Token': self.brave_api_key
                },
                'enabled': True
            }
        
        # DuckDuckGo (backup - sin API key)
        engines['duckduckgo'] = {
            'url': 'https://api.duckduckgo.com/',
            'headers': {'User-Agent': 'PhishingDetector/1.0'},
            'enabled': True
        }
        
        return engines
    
    async def search_domain_reputation(self, domain: str) -> Dict[str, Any]:
        """Busca la reputación de un dominio en internet."""
        search_results = {
            'domain': domain,
            'search_performed': True,
            'engines_used': [],
            'reputation_score': 0.0,
            'findings': [],
            'phishing_reports': [],
            'security_warnings': [],
            'total_results': 0
        }
        
        try:
            # Consultas específicas para el dominio
            queries = [
                f'"{domain}" phishing scam',
                f'"{domain}" malicious site warning',
                f'"{domain}" security threat report',
                f'site:{domain} security warning'
            ]
            
            for query in queries:
                try:
                    results = await self._perform_search(query)
                    if results:
                        search_results['engines_used'].extend(results.get('engines_used', []))
                        search_results['total_results'] += results.get('total_results', 0)
                        
                        # Analizar resultados
                        analysis = self._analyze_search_results(results, domain)
                        self._merge_analysis(search_results, analysis)
                        
                except Exception as e:
                    logger.error(f"Error en búsqueda '{query}': {e}")
            
            # Calcular puntuación de reputación
            search_results['reputation_score'] = self._calculate_reputation_score(search_results)
            
        except Exception as e:
            logger.error(f"Error en búsqueda de reputación para {domain}: {e}")
            search_results['error'] = str(e)
            search_results['search_performed'] = False
        
        return search_results
    
    async def search_email_content_intelligence(self, email_content: str) -> Dict[str, Any]:
        """Busca información sobre contenido específico del email."""
        # Extraer elementos clave para buscar
        elements = self._extract_searchable_elements(email_content)
        
        intelligence = {
            'elements_searched': elements,
            'findings': [],
            'similar_campaigns': [],
            'threat_reports': [],
            'total_searches': 0
        }
        
        try:
            for element in elements:
                if element['type'] == 'suspicious_phrase':
                    results = await self._search_phrase_intelligence(element['value'])
                elif element['type'] == 'hash':
                    results = await self._search_hash_intelligence(element['value'])
                elif element['type'] == 'url_pattern':
                    results = await self._search_url_pattern_intelligence(element['value'])
                
                if results:
                    intelligence['findings'].extend(results.get('findings', []))
                    intelligence['total_searches'] += 1
                    
        except Exception as e:
            logger.error(f"Error en búsqueda de inteligencia: {e}")
            intelligence['error'] = str(e)
        
        return intelligence
    
    def _extract_searchable_elements(self, email_content: str) -> List[Dict[str, str]]:
        """Extrae elementos del email que se pueden buscar."""
        elements = []
        
        # Frases sospechosas específicas
        suspicious_phrases = [
            r'verify.*account.*24.*hours',
            r'urgent.*action.*required',
            r'suspicious.*activity.*detected',
            r'click.*here.*verify',
            r'your.*account.*suspended'
        ]
        
        for pattern in suspicious_phrases:
            matches = re.findall(pattern, email_content, re.IGNORECASE)
            for match in matches:
                elements.append({
                    'type': 'suspicious_phrase',
                    'value': match,
                    'pattern': pattern
                })
        
        # URLs sospechosas
        url_pattern = r'https?://[^\s<>"]+|www\.[^\s<>"]+'
        urls = re.findall(url_pattern, email_content, re.IGNORECASE)
        for url in urls:
            elements.append({
                'type': 'url_pattern',
                'value': url
            })
        
        # Crear hash del contenido para buscar campañas similares
        import hashlib
        content_hash = hashlib.md5(email_content.encode()).hexdigest()[:16]
        elements.append({
            'type': 'hash',
            'value': content_hash
        })
        
        return elements
    
    async def _perform_search(self, query: str) -> Optional[Dict[str, Any]]:
        """Realiza búsqueda usando el motor disponible."""
        # Intentar con Brave primero, luego DuckDuckGo
        for engine_name, engine_config in self.search_engines.items():
            if not engine_config['enabled']:
                continue
                
            try:
                if engine_name == 'brave':
                    return await self._brave_search(query, engine_config)
                elif engine_name == 'duckduckgo':
                    return await self._duckduckgo_search(query, engine_config)
            except Exception as e:
                logger.error(f"Error en {engine_name}: {e}")
                continue
        
        return None
    
    async def _brave_search(self, query: str, config: Dict) -> Dict[str, Any]:
        """Realiza búsqueda usando Brave Search API."""
        params = {
            'q': query,
            'count': self.max_results,
            'search_lang': 'en',
            'country': 'US',
            'safesearch': 'off'
        }
        
        async with aiohttp.ClientSession() as session:
            async with session.get(
                config['url'],
                headers=config['headers'],
                params=params
            ) as response:
                if response.status == 200:
                    data = await response.json()
                    return {
                        'engine': 'brave',
                        'query': query,
                        'results': data.get('web', {}).get('results', []),
                        'total_results': len(data.get('web', {}).get('results', [])),
                        'engines_used': ['brave']
                    }
                else:
                    raise Exception(f"Brave API error: {response.status}")
    
    async def _duckduckgo_search(self, query: str, config: Dict) -> Dict[str, Any]:
        """Realiza búsqueda usando DuckDuckGo (método simplificado)."""
        # DuckDuckGo no tiene API oficial, usamos búsqueda instant answer
        params = {
            'q': query,
            'format': 'json',
            'no_redirect': '1',
            'no_html': '1',
            'skip_disambig': '1'
        }
        
        async with aiohttp.ClientSession() as session:
            async with session.get(
                config['url'],
                headers=config['headers'],
                params=params
            ) as response:
                if response.status == 200:
                    data = await response.json()
                    return {
                        'engine': 'duckduckgo',
                        'query': query,
                        'results': [data] if data.get('AbstractText') else [],
                        'total_results': 1 if data.get('AbstractText') else 0,
                        'engines_used': ['duckduckgo']
                    }
                else:
                    raise Exception(f"DuckDuckGo error: {response.status}")
    
    def _analyze_search_results(self, results: Dict[str, Any], domain: str) -> Dict[str, Any]:
        """Analiza los resultados de búsqueda para extraer información relevante."""
        analysis = {
            'phishing_indicators': [],
            'security_warnings': [],
            'reputation_signals': [],
            'threat_score': 0.0
        }
        
        search_results = results.get('results', [])
        
        for result in search_results:
            title = result.get('title', '').lower()
            description = result.get('description', '').lower()
            url = result.get('url', '').lower()
            
            # Buscar indicadores de phishing
            phishing_keywords = [
                'phishing', 'scam', 'fraud', 'malicious', 'dangerous',
                'security warning', 'threat', 'blacklist', 'malware'
            ]
            
            for keyword in phishing_keywords:
                if keyword in title or keyword in description:
                    analysis['phishing_indicators'].append({
                        'keyword': keyword,
                        'source': result.get('url', ''),
                        'title': result.get('title', ''),
                        'context': description[:200]
                    })
                    analysis['threat_score'] += 0.2
            
            # Verificar si aparece en listas de seguridad
            security_sources = [
                'virustotal.com', 'urlvoid.com', 'safebrowsing.google.com',
                'phishtank.com', 'openphish.com', 'malwaredomainlist.com'
            ]
            
            for source in security_sources:
                if source in url and domain in description:
                    analysis['security_warnings'].append({
                        'source': source,
                        'url': result.get('url', ''),
                        'title': result.get('title', ''),
                        'description': description[:200]
                    })
                    analysis['threat_score'] += 0.5
        
        return analysis
    
    async def _search_phrase_intelligence(self, phrase: str) -> Dict[str, Any]:
        """Busca inteligencia sobre frases sospechosas específicas."""
        query = f'"{phrase}" phishing email campaign'
        results = await self._perform_search(query)
        
        if not results:
            return {'findings': []}
        
        findings = []
        for result in results.get('results', []):
            if any(word in result.get('title', '').lower() + result.get('description', '').lower() 
                   for word in ['campaign', 'attack', 'phishing', 'malware']):
                findings.append({
                    'type': 'phrase_match',
                    'phrase': phrase,
                    'source': result.get('url', ''),
                    'title': result.get('title', ''),
                    'relevance': 'high'
                })
        
        return {'findings': findings}
    
    async def _search_hash_intelligence(self, content_hash: str) -> Dict[str, Any]:
        """Busca inteligencia sobre hashes de contenido."""
        query = f'"{content_hash}" malware hash'
        results = await self._perform_search(query)
        
        return {'findings': []} if not results else {'findings': results.get('results', [])}
    
    async def _search_url_pattern_intelligence(self, url: str) -> Dict[str, Any]:
        """Busca inteligencia sobre patrones de URL."""
        domain = urllib.parse.urlparse(url).netloc if '://' in url else url.split('/')[0]
        query = f'"{domain}" malicious URL report'
        results = await self._perform_search(query)
        
        return {'findings': []} if not results else {'findings': results.get('results', [])}
    
    def _merge_analysis(self, search_results: Dict, analysis: Dict):
        """Combina análisis de múltiples búsquedas."""
        search_results['findings'].extend(analysis.get('phishing_indicators', []))
        search_results['security_warnings'].extend(analysis.get('security_warnings', []))
        search_results['phishing_reports'].extend(analysis.get('phishing_indicators', []))
    
    def _calculate_reputation_score(self, search_results: Dict) -> float:
        """Calcula puntuación de reputación basada en hallazgos."""
        score = 0.0
        
        # Penalizar por reportes de phishing
        phishing_reports = len(search_results.get('phishing_reports', []))
        score += min(phishing_reports * 0.3, 0.8)
        
        # Penalizar por advertencias de seguridad
        security_warnings = len(search_results.get('security_warnings', []))
        score += min(security_warnings * 0.4, 0.9)
        
        # Penalizar por múltiples hallazgos
        total_findings = len(search_results.get('findings', []))
        if total_findings > 3:
            score += 0.2
        
        return min(score, 1.0)
    
    def get_intelligence_summary(self, domain_intel: Dict, content_intel: Dict) -> str:
        """Genera resumen legible de la inteligencia web."""
        summary = "🌐 INTELIGENCIA WEB\n"
        summary += "=" * 30 + "\n\n"
        
        # Reputación del dominio
        if domain_intel.get('search_performed'):
            reputation = domain_intel['reputation_score']
            if reputation > 0.7:
                summary += "🔴 DOMINIO CON MALA REPUTACIÓN\n"
            elif reputation > 0.3:
                summary += "🟡 Dominio con reportes sospechosos\n"
            else:
                summary += "✅ Sin reportes negativos encontrados\n"
            
            summary += f"📊 Puntuación de reputación: {reputation*100:.1f}%\n"
            summary += f"🔍 Resultados encontrados: {domain_intel['total_results']}\n\n"
            
            # Reportes específicos
            if domain_intel.get('phishing_reports'):
                summary += "⚠️ REPORTES DE PHISHING:\n"
                for report in domain_intel['phishing_reports'][:3]:
                    summary += f"  • {report.get('keyword', 'N/A')}: {report.get('title', 'N/A')}\n"
            
            if domain_intel.get('security_warnings'):
                summary += "\n🛡️ ADVERTENCIAS DE SEGURIDAD:\n"
                for warning in domain_intel['security_warnings'][:3]:
                    summary += f"  • {warning.get('source', 'N/A')}: {warning.get('title', 'N/A')}\n"
        else:
            summary += "❌ No se pudo realizar búsqueda de reputación\n"
        
        # Inteligencia de contenido
        summary += f"\n📧 ANÁLISIS DE CONTENIDO:\n"
        summary += f"🔍 Elementos analizados: {len(content_intel.get('elements_searched', []))}\n"
        summary += f"📄 Búsquedas realizadas: {content_intel.get('total_searches', 0)}\n"
        
        if content_intel.get('findings'):
            summary += f"⚠️ Hallazgos sospechosos: {len(content_intel['findings'])}\n"
        
        return summary


# Configuración de ejemplo
EXAMPLE_CONFIG = {
    'brave_api_key': 'your_brave_api_key_here',  # Obtener en https://api.search.brave.com/
    'max_search_results': 5,
    'search_timeout': 10  # segundos
} 