"""Configuración centralizada del proyecto."""

import os
from pathlib import Path
from typing import Set
from dotenv import load_dotenv

# Rutas del proyecto
PROJECT_ROOT = Path(__file__).parent
DATA_DIR = PROJECT_ROOT / "data"
CACHE_DIR = DATA_DIR / "cache"
CACHE_DIR.mkdir(exist_ok=True)

# Cargar variables de entorno
load_dotenv()

# Configuración de la API
DEFAULT_MODEL = "gpt-3.5-turbo"
DEFAULT_TEMPERATURE = 0
MAX_AGENT_ITERATIONS = 5

# Configuración del LLM
LLM_CONFIG = {
    "api_key": os.getenv("OPENAI_API_KEY"),
    "api_base": os.getenv("OPENAI_API_BASE", "https://api.openai.com/v1"),
    "model_name": os.getenv("MODEL_NAME", "gpt-4-vision-preview"),
    "max_tokens": 4096,
    "temperature": 0.7
}

# Dominios bancarios oficiales españoles (versión extendida)
OFFICIAL_BANK_DOMAINS: Set[str] = {
    # Grandes bancos
    "bbva.es", "bbva.com",
    "santander.es", "bancosantander.es",
    "caixabank.es", "lacaixa.es",
    "bankia.es",
    "bancsabadell.com", "sabadell.com",
    "ing.es",
    "bankinter.es", "bankinter.com",
    "unicaja.es", "unicajabanco.es",
    "kutxabank.es",
    "abanca.com",
    "liberbank.es",
    "ibercaja.es",
    "cajamar.es",
    
    # Bancos online y fintech
    "openbank.es",
    "evobank.es",
    "selfbank.es",
    "pibank.es",
    
    # Instituciones oficiales
    "bde.es",  # Banco de España
    "sepblac.es",  # SEPBLAC
}

# Patrones sospechosos en español
SUSPICIOUS_PATTERNS = [
    r"verificar.*cuenta",
    r"suspender.*cuenta",
    r"bloquear.*cuenta", 
    r"actividad sospechosa",
    r"hacer.*clic.*aquí",
    r"urgente",
    r"inmediatamente",
    r"24.*horas?",
    r"datos.*personales",
    r"confirmar.*identidad",
    r"actualizar.*información",
    r"seguridad.*comprometida",
    r"transfer.*dinero",
    r"premio.*lotería",
    r"ganador.*concurso",
    r"caducidad.*tarjeta",
]

# Configuración de logging
LOG_FORMAT = "%(asctime)s - %(name)s - %(levelname)s - %(message)s"
LOG_LEVEL = os.getenv("LOG_LEVEL", "INFO")

# Configuración de análisis de emails
EMAIL_CONFIG = {
    "max_image_size": (1024, 1024),  # Tamaño máximo de imagen a procesar
    "supported_image_formats": ["jpg", "jpeg", "png", "gif", "webp"],
    "max_email_size": 10 * 1024 * 1024  # 10MB máximo
}

# Configuración de Threat Intelligence
THREAT_INTELLIGENCE_CONFIG = {
    "phishtank_api_key": os.getenv("PHISHTANK_API_KEY"),
    "custom_threat_sources": [
        {
            "name": "abuse_ch_urlhaus",
            "url": "https://urlhaus.abuse.ch/downloads/text/",
            "update_frequency": 1800  # 30 minutos
        },
        {
            "name": "malware_domains",
            "url": "http://mirror1.malwaredomains.com/files/domains.txt",
            "update_frequency": 3600  # 1 hora
        },
        {
            "name": "cybercrime_tracker",
            "url": "https://cybercrime-tracker.net/all.php",
            "update_frequency": 3600
        }
    ],
    "cache_directory": str(CACHE_DIR),
    "max_cache_age": 3600  # 1 hora por defecto
}

# Configuración de análisis de attachments
ATTACHMENT_ANALYSIS_CONFIG = {
    "max_file_size": 50 * 1024 * 1024,  # 50MB
    "scan_archives": True,
    "detailed_analysis": True,
    "quarantine_dangerous": False,  # Por seguridad, no mover archivos automáticamente
    "supported_archive_formats": ["zip", "rar", "7z", "tar", "gz"],
    "signature_verification": True
}

# Configuración de búsqueda web
WEB_SEARCH_CONFIG = {
    "brave_api_key": os.getenv("BRAVE_API_KEY"),
    "duckduckgo_enabled": True,
    "max_search_results": 5,
    "search_timeout": 10,  # segundos
    "enable_domain_reputation": True,
    "enable_content_intelligence": True,
    "cache_search_results": True,
    "cache_duration": 1800  # 30 minutos
}

# Configuración completa para el agente mejorado
ENHANCED_AGENT_CONFIG = {
    "threat_intelligence": THREAT_INTELLIGENCE_CONFIG,
    "attachment_analysis": ATTACHMENT_ANALYSIS_CONFIG,
    "web_search": WEB_SEARCH_CONFIG,
    "email_analysis": EMAIL_CONFIG,
    "llm": LLM_CONFIG,
    
    # Configuración de análisis
    "enable_web_search": True,
    "enable_threat_intel": True,
    "enable_attachment_analysis": True,
    "parallel_analysis": True,  # Ejecutar análisis en paralelo cuando sea posible
    
    # Configuración de reportes
    "detailed_reports": True,
    "include_confidence_scores": True,
    "include_source_attribution": True
}

def get_env_var(key: str, default: str = "") -> str:
    """Obtiene una variable de entorno con valor por defecto."""
    return os.getenv(key, default)

def is_production() -> bool:
    """Determina si estamos en producción."""
    return get_env_var("ENVIRONMENT", "development").lower() == "production"

def get_threat_intel_config() -> dict:
    """Obtiene configuración específica de threat intelligence."""
    return THREAT_INTELLIGENCE_CONFIG

def get_attachment_config() -> dict:
    """Obtiene configuración específica de análisis de attachments."""
    return ATTACHMENT_ANALYSIS_CONFIG

def get_web_search_config() -> dict:
    """Obtiene configuración específica de búsqueda web."""
    return WEB_SEARCH_CONFIG

def get_enhanced_agent_config() -> dict:
    """Obtiene configuración completa para el agente mejorado."""
    return ENHANCED_AGENT_CONFIG 