"""Herramienta para analizar el contenido de un correo electrónico.
En una versión futura, este módulo se integrará como una Tool de LangChain.
"""

import re
from email.parser import Parser
from typing import Dict, List, Any
from urllib.parse import urlparse

try:
    from bs4 import BeautifulSoup
    HAS_BS4 = True
except ImportError:
    HAS_BS4 = False

__all__ = ["parse_email"]

# Regex mejorado para URLs
EMAIL_LINK_REGEX = re.compile(
    r"https?://(?:[-\w.])+(?:[:\d]+)?(?:/(?:[\w/_.])*)?(?:\?(?:[\w&=%.])*)?(?:#(?:[\w.])*)?",
    re.IGNORECASE
)

# Patrones sospechosos comunes en phishing
SUSPICIOUS_PATTERNS = [
    r"verificar.*cuenta",
    r"suspender.*cuenta", 
    r"actividad sospechosa",
    r"hacer.*clic.*aquí",
    r"urgente",
    r"inmediatamente",
    r"24.*horas?",
    r"datos.*personales",
]

SUSPICIOUS_REGEX = [re.compile(pattern, re.IGNORECASE) for pattern in SUSPICIOUS_PATTERNS]


def extract_text_from_html(html_content: str) -> str:
    """Extrae texto plano de contenido HTML."""
    if not HAS_BS4:
        # Fallback simple sin BeautifulSoup
        return re.sub(r'<[^>]+>', '', html_content)
    
    soup = BeautifulSoup(html_content, 'html.parser')
    return soup.get_text(separator=' ', strip=True)


def detect_suspicious_patterns(text: str) -> List[str]:
    """Detecta patrones sospechosos en el texto."""
    found_patterns = []
    for pattern_regex in SUSPICIOUS_REGEX:
        matches = pattern_regex.findall(text)
        found_patterns.extend(matches)
    return found_patterns


def parse_email(raw_email: str) -> Dict[str, Any]:
    """Parsea un correo electrónico en texto plano y extrae metadatos básicos.

    Args:
        raw_email: Contenido completo del correo como cadena.

    Returns:
        Dict con claves: subject, from, to, body, links, suspicious_patterns.
    """
    # Intenta analizar con email.parser, pero si falla, procesa manualmente
    try:
        email_obj = Parser().parsestr(raw_email)
        subject = email_obj.get("subject", "") or ""
        sender = email_obj.get("from", "") or ""
        to = email_obj.get("to", "") or ""
        
        # Obtener el cuerpo del mensaje (método simplificado)
        if email_obj.is_multipart():
            body_text = ""
            for part in email_obj.walk():
                if part.get_content_type() in ["text/plain", "text/html"]:
                    payload = part.get_payload(decode=True)
                    if payload and isinstance(payload, bytes):
                        body_text = payload.decode('utf-8', errors='ignore')
                    elif payload:
                        body_text = str(payload)
                        if part.get_content_type() == "text/html":
                            body_text = extract_text_from_html(body_text)
                        break
        else:
            payload = email_obj.get_payload(decode=True)
            if payload and isinstance(payload, bytes):
                body_text = payload.decode('utf-8', errors='ignore')
            elif payload:
                body_text = str(payload)
            else:
                body_text = raw_email
            
    except Exception:
        # Fallback manual si falla el parsing
        lines = raw_email.split('\n')
        subject = ""
        sender = ""
        to = ""
        body_text = raw_email
        
        # Intenta extraer headers básicos
        for line in lines[:10]:  # Solo los primeros 10 líneas para headers
            if line.lower().startswith("asunto:") or line.lower().startswith("subject:"):
                subject = line.split(":", 1)[1].strip()
            elif line.lower().startswith("de:") or line.lower().startswith("from:"):
                sender = line.split(":", 1)[1].strip()
            elif line.lower().startswith("para:") or line.lower().startswith("to:"):
                to = line.split(":", 1)[1].strip()

    # Extraer enlaces
    links = EMAIL_LINK_REGEX.findall(body_text)
    
    # Detectar patrones sospechosos
    suspicious_patterns = detect_suspicious_patterns(body_text + " " + subject)
    
    # Extraer dominios de los enlaces
    domains = []
    for link in links:
        try:
            domain = urlparse(link).netloc
            if domain:
                domains.append(domain.lower())
        except Exception:
            continue

    return {
        "subject": subject.strip(),
        "from": sender.strip(),
        "to": to.strip(),
        "body": body_text.strip(),
        "links": links,
        "domains": list(set(domains)),  # Dominios únicos
        "suspicious_patterns": suspicious_patterns,
        "link_count": len(links),
        "has_multiple_links": len(links) > 1,
    } 