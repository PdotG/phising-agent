"""Módulo para obtener dominios maliciosos de fuentes de threat intelligence."""

import asyncio
import aiohttp
import logging
import json
import csv
import io
from typing import Set, List, Dict, Optional, Any
from datetime import datetime, timedelta
from pathlib import Path
import re

logger = logging.getLogger(__name__)

class ThreatIntelligenceProvider:
    """Proveedor base para fuentes de threat intelligence."""
    
    def __init__(self, name: str, url: str, update_frequency: int = 3600):
        self.name = name
        self.url = url
        self.update_frequency = update_frequency  # segundos
        self.last_update = None
        self.cache_file = Path(f"data/cache/{name}_domains.json")
        self.cache_file.parent.mkdir(exist_ok=True)
    
    async def fetch_domains(self) -> Set[str]:
        """Obtiene dominios maliciosos de la fuente. Debe ser implementado por subclases."""
        raise NotImplementedError
    
    async def get_domains(self, force_update: bool = False) -> Set[str]:
        """Obtiene dominios con cache."""
        if not force_update and self._is_cache_valid():
            return self._load_cache()
        
        try:
            domains = await self.fetch_domains()
            self._save_cache(domains)
            self.last_update = datetime.now()
            logger.info(f"{self.name}: Obtenidos {len(domains)} dominios")
            return domains
        except Exception as e:
            logger.error(f"Error obteniendo dominios de {self.name}: {e}")
            # Intentar cargar cache como fallback
            return self._load_cache() if self.cache_file.exists() else set()
    
    def _is_cache_valid(self) -> bool:
        """Verifica si el cache es válido."""
        if not self.cache_file.exists():
            return False
        
        cache_age = datetime.now() - datetime.fromtimestamp(self.cache_file.stat().st_mtime)
        return cache_age.total_seconds() < self.update_frequency
    
    def _load_cache(self) -> Set[str]:
        """Carga dominios desde cache."""
        try:
            with open(self.cache_file, 'r') as f:
                data = json.load(f)
                return set(data.get('domains', []))
        except Exception as e:
            logger.error(f"Error cargando cache de {self.name}: {e}")
            return set()
    
    def _save_cache(self, domains: Set[str]):
        """Guarda dominios en cache."""
        try:
            with open(self.cache_file, 'w') as f:
                json.dump({
                    'domains': list(domains),
                    'timestamp': datetime.now().isoformat(),
                    'source': self.name
                }, f)
        except Exception as e:
            logger.error(f"Error guardando cache de {self.name}: {e}")


class PhishTankProvider(ThreatIntelligenceProvider):
    """Proveedor de PhishTank - Base de datos colaborativa de phishing."""
    
    def __init__(self, api_key: Optional[str] = None):
        url = "http://data.phishtank.com/data/online-valid.csv"
        if api_key:
            url += f"?apikey={api_key}&format=csv"
        super().__init__("phishtank", url, 3600)  # Actualizar cada hora
    
    async def fetch_domains(self) -> Set[str]:
        """Obtiene dominios de PhishTank."""
        domains = set()
        
        async with aiohttp.ClientSession() as session:
            async with session.get(self.url) as response:
                if response.status == 200:
                    content = await response.text()
                    
                    # Parsear CSV
                    reader = csv.DictReader(io.StringIO(content))
                    for row in reader:
                        url = row.get('url', '')
                        if url:
                            domain = self._extract_domain(url)
                            if domain:
                                domains.add(domain)
                else:
                    raise Exception(f"HTTP {response.status}: {await response.text()}")
        
        return domains
    
    def _extract_domain(self, url: str) -> Optional[str]:
        """Extrae dominio de una URL."""
        try:
            # Remover protocolo
            if '://' in url:
                url = url.split('://', 1)[1]
            
            # Obtener solo el dominio
            domain = url.split('/')[0].split('?')[0].split('#')[0]
            
            # Validar que sea un dominio válido
            if '.' in domain and not any(c in domain for c in [' ', '\t', '\n']):
                return domain.lower()
        except Exception:
            pass
        return None


class OpenPhishProvider(ThreatIntelligenceProvider):
    """Proveedor de OpenPhish - Feed gratuito de URLs de phishing."""
    
    def __init__(self):
        super().__init__("openphish", "https://openphish.com/feed.txt", 1800)  # 30 min
    
    async def fetch_domains(self) -> Set[str]:
        """Obtiene dominios de OpenPhish."""
        domains = set()
        
        async with aiohttp.ClientSession() as session:
            async with session.get(self.url) as response:
                if response.status == 200:
                    content = await response.text()
                    
                    # Cada línea es una URL
                    for line in content.strip().split('\n'):
                        if line.strip():
                            domain = self._extract_domain(line.strip())
                            if domain:
                                domains.add(domain)
                else:
                    raise Exception(f"HTTP {response.status}")
        
        return domains
    
    def _extract_domain(self, url: str) -> Optional[str]:
        """Extrae dominio de una URL."""
        try:
            if '://' in url:
                url = url.split('://', 1)[1]
            
            domain = url.split('/')[0].split('?')[0]
            if '.' in domain:
                return domain.lower()
        except Exception:
            pass
        return None


class URLVoidProvider(ThreatIntelligenceProvider):
    """Proveedor personalizable para listas de dominios en formato texto."""
    
    def __init__(self, name: str, url: str, update_frequency: int = 3600):
        super().__init__(name, url, update_frequency)
    
    async def fetch_domains(self) -> Set[str]:
        """Obtiene dominios de un feed de texto plano."""
        domains = set()
        
        async with aiohttp.ClientSession() as session:
            async with session.get(self.url) as response:
                if response.status == 200:
                    content = await response.text()
                    
                    # Cada línea puede ser un dominio o URL
                    for line in content.strip().split('\n'):
                        line = line.strip()
                        if line and not line.startswith('#'):
                            domain = self._extract_domain(line)
                            if domain:
                                domains.add(domain)
                else:
                    raise Exception(f"HTTP {response.status}")
        
        return domains
    
    def _extract_domain(self, text: str) -> Optional[str]:
        """Extrae dominio de texto."""
        try:
            # Remover protocolo si existe
            if '://' in text:
                text = text.split('://', 1)[1]
            
            # Obtener solo el dominio
            domain = text.split('/')[0].split('?')[0].split('#')[0]
            
            # Validar formato de dominio
            if re.match(r'^[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$', domain):
                return domain.lower()
        except Exception:
            pass
        return None


class ThreatIntelligenceManager:
    """Gestor centralizado de fuentes de threat intelligence."""
    
    def __init__(self, config: Optional[Dict] = None):
        self.config = config or {}
        self.providers: List[ThreatIntelligenceProvider] = []
        self._setup_default_providers()
        self._setup_custom_providers()
    
    def _setup_default_providers(self):
        """Configura proveedores por defecto."""
        # PhishTank
        phishtank_key = self.config.get('phishtank_api_key')
        self.providers.append(PhishTankProvider(phishtank_key))
        
        # OpenPhish
        self.providers.append(OpenPhishProvider())
    
    def _setup_custom_providers(self):
        """Configura proveedores personalizados desde config."""
        custom_sources = self.config.get('custom_threat_sources', [])
        
        for source in custom_sources:
            provider = URLVoidProvider(
                name=source['name'],
                url=source['url'],
                update_frequency=source.get('update_frequency', 3600)
            )
            self.providers.append(provider)
    
    def add_custom_source(self, name: str, url: str, update_frequency: int = 3600):
        """Añade una fuente personalizada."""
        provider = URLVoidProvider(name, url, update_frequency)
        self.providers.append(provider)
        logger.info(f"Añadida fuente personalizada: {name}")
    
    async def get_all_malicious_domains(self, force_update: bool = False) -> Set[str]:
        """Obtiene todos los dominios maliciosos de todas las fuentes."""
        all_domains = set()
        
        # Obtener dominios de todas las fuentes en paralelo
        tasks = [provider.get_domains(force_update) for provider in self.providers]
        results = await asyncio.gather(*tasks, return_exceptions=True)
        
        for i, result in enumerate(results):
            if isinstance(result, Exception):
                logger.error(f"Error en proveedor {self.providers[i].name}: {result}")
            elif isinstance(result, set):
                all_domains.update(result)
        
        logger.info(f"Total dominios maliciosos obtenidos: {len(all_domains)}")
        return all_domains
    
    async def check_domain(self, domain: str, force_update: bool = False) -> Dict[str, Any]:
        """Verifica si un dominio está en las listas de amenazas."""
        malicious_domains = await self.get_all_malicious_domains(force_update)
        
        # Verificar dominio exacto
        is_malicious = domain.lower() in malicious_domains
        
        # Verificar subdominios (ej: si evil.com está en la lista, sub.evil.com también es malicioso)
        parent_malicious = False
        for malicious in malicious_domains:
            if domain.lower().endswith('.' + malicious):
                parent_malicious = True
                break
        
        return {
            "domain": domain,
            "is_malicious": is_malicious or parent_malicious,
            "exact_match": is_malicious,
            "parent_match": parent_malicious,
            "total_sources": len(self.providers),
            "timestamp": datetime.now().isoformat()
        }
    
    def get_provider_status(self) -> List[Dict[str, Any]]:
        """Obtiene el estado de todos los proveedores."""
        status = []
        for provider in self.providers:
            status.append({
                "name": provider.name,
                "url": provider.url,
                "last_update": provider.last_update.isoformat() if provider.last_update else None,
                "cache_exists": provider.cache_file.exists(),
                "update_frequency": provider.update_frequency
            })
        return status


# Ejemplo de configuración
EXAMPLE_CONFIG = {
    "phishtank_api_key": "your_api_key_here",  # Opcional pero recomendado
    "custom_threat_sources": [
        {
            "name": "abuse_ch",
            "url": "https://urlhaus.abuse.ch/downloads/text/",
            "update_frequency": 1800
        },
        {
            "name": "malware_domains",
            "url": "http://mirror1.malwaredomains.com/files/domains.txt",
            "update_frequency": 3600
        }
    ]
} 