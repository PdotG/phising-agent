"""Herramienta que verifica si un dominio es oficial o no."""

from urllib.parse import urlparse
from app.utils.official_domains import is_official_domain

__all__ = ["classify_domain"]


def extract_domain(url: str) -> str:
    """Extrae el dominio de una URL."""
    parsed = urlparse(url)
    return parsed.netloc.lower()


def classify_domain(url: str) -> str:
    """Clasifica el dominio asociado a una URL.

    Returns: "official" o "unknown".
    """
    domain = extract_domain(url)
    if is_official_domain(domain):
        return "official"
    return "unknown" 