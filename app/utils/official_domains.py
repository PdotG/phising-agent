"""Módulo que contiene la lista oficial de dominios bancarios españoles.
En una aplicación real, esta lista podría mantenerse en una base de datos o
obtenerse de una fuente oficial del Banco de España.
"""

OFFICIAL_BANK_DOMAINS = {
    "bbva.es",
    "santander.es",
    "caixabank.es",
    "bankia.es",
    "bancsabadell.com",
    "ing.es",
}

def is_official_domain(domain: str) -> bool:
    """Comprueba si el dominio pertenece a la lista de dominios bancarios oficiales."""
    return domain.lower() in OFFICIAL_BANK_DOMAINS 