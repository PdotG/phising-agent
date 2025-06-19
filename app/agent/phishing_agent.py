"""PhishingAgent basado en LangChain.

Este archivo contendrá la lógica para instanciar un AgentExecutor que combine:
- Un LLM (p.ej. DeepSeek vía la interfaz OpenAI de LangChain)
- Herramientas: EmailParserTool, DomainVerifierTool, WebSearchTool (Tavily)

El resultado será una clasificación y un informe JSON estructurado.
"""

from __future__ import annotations
import os
from typing import Optional

from dotenv import load_dotenv
from langchain.agents import AgentExecutor, create_structured_chat_agent
from langchain.prompts import ChatPromptTemplate
from langchain.tools import Tool
from langchain_core.language_models import BaseChatModel
from langchain.llms import OpenAI as ChatOpenAI  # Fallback

try:
    from langchain_community.tools.tavily_search import TavilySearchResults
except ImportError:
    TavilySearchResults = None

from app.tools.email_parser import parse_email
from app.tools.domain_verifier import classify_domain

# Cargar variables de entorno
load_dotenv()

# Prompt del sistema mejorado
SYSTEM_PROMPT = """Eres un agente experto en ciberseguridad especializado en detectar correos de phishing bancario dirigidos a usuarios en España.

Tu tarea es analizar correos electrónicos y determinar si son intentos de phishing bancario. 

Criterios de análisis:
1. Remitente: ¿Viene de un dominio bancario oficial español?
2. Urgencia: ¿Usa lenguaje de urgencia o amenazas?
3. Enlaces: ¿Los enlaces van a dominios oficiales o sospechosos?
4. Contenido: ¿Solicita información sensible o acciones inmediatas?
5. Calidad: ¿Contiene errores ortográficos o de formato?

Debes responder con un JSON estructurado que contenga:
- "classification": "phishing" | "legitimate" | "suspicious"
- "confidence": número entre 0 y 1
- "reasons": lista de razones específicas
- "risk_indicators": lista de indicadores de riesgo encontrados
- "recommendation": recomendación para el usuario
"""


def get_tools() -> list[Tool]:
    """Construye la lista de herramientas personalizadas."""

    def _parse_email_tool(email_content: str) -> str:
        """Herramienta para parsear correos electrónicos."""
        result = parse_email(email_content)
        return f"Análisis del correo:\n{result}"

    def _domain_verifier_tool(url: str) -> str:
        """Herramienta para verificar dominios."""
        classification = classify_domain(url)
        return f"Clasificación del dominio '{url}': {classification}"

    tools: list[Tool] = [
        Tool(
            name="EmailParser",
            func=_parse_email_tool,
            description="Extrae asunto, remitente, cuerpo y enlaces de un correo electrónico.",
        ),
        Tool(
            name="DomainVerifier",
            func=_domain_verifier_tool,
            description="Clasifica un dominio como oficial, en lista negra o desconocido.",
        ),
    ]

    # Añadir Tavily si está disponible y configurado
    if TavilySearchResults and os.getenv("TAVILY_API_KEY"):
        tavily_search = TavilySearchResults(max_results=3)
        tools.append(
            Tool(
                name="WebSearch",
                func=tavily_search.run,
                description="Busca información en web sobre dominios sospechosos o bancos.",
            )
        )

    return tools


def build_agent(model: Optional[BaseChatModel] = None) -> AgentExecutor:
    """Devuelve un AgentExecutor configurado con las herramientas necesarias."""
    if model is None:
        api_key = os.getenv("OPENAI_API_KEY")
        api_base = os.getenv("OPENAI_API_BASE")
        
        if not api_key:
            raise ValueError("OPENAI_API_KEY no configurada. Revisa tu archivo .env")
            
        model = ChatOpenAI(
            model="gpt-3.5-turbo",
            temperature=0,
            openai_api_key=api_key,
            openai_api_base=api_base if api_base else None,
        )

    prompt = ChatPromptTemplate.from_messages(
        [
            ("system", SYSTEM_PROMPT),
            ("user", "Analiza este correo electrónico: {input}"),
            ("assistant", "Voy a analizar este correo paso a paso usando mis herramientas disponibles."),
        ]
    )

    agent = create_structured_chat_agent(model, get_tools(), prompt)  # type: ignore
    return AgentExecutor.from_agent_and_tools(
        agent=agent,
        tools=get_tools(),
        verbose=True,
        handle_parsing_errors=True,
        max_iterations=5,
    ) 