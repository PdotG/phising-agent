"""Punto de entrada principal para ejecutar el agente multimodal.

Ejemplo de uso:
    python -m app.main --email-file ../data/example_phishing_email.txt
    python -m app.main --email-file ../data/example_phishing_email.txt --output-file result.json
"""

import argparse
import json
import logging
import asyncio
from pathlib import Path
from typing import Dict, Any

from app.agent.multimodal_phishing_agent import MultimodalPhishingAgent


def setup_logging(verbose: bool = False):
    """Configura el logging básico."""
    level = logging.DEBUG if verbose else logging.INFO
    logging.basicConfig(
        level=level,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    )


def save_result_to_file(result: Dict[str, Any], output_file: Path):
    """Guarda el resultado en un archivo JSON."""
    try:
        with output_file.open('w', encoding='utf-8') as f:
            json.dump(result, f, indent=2, ensure_ascii=False)
        print(f"✅ Resultado guardado en: {output_file}")
    except Exception as e:
        print(f"❌ Error al guardar resultado: {e}")


async def analyze_email(args: argparse.Namespace) -> int:
    """Ejecuta el análisis del email."""
    logger = logging.getLogger(__name__)
    
    try:
        # Leer el contenido del correo
        logger.info(f"Leyendo correo desde: {args.email_file}")
        email_content = args.email_file.read_text(encoding="utf-8")
        
        if not email_content.strip():
            print("❌ Error: El archivo de correo está vacío.")
            return 1

        # Construir y ejecutar el agente multimodal
        logger.info("Iniciando análisis multimodal...")
        agent = MultimodalPhishingAgent()
        
        if args.simple:
            # Análisis simple - solo clasificación
            classification = await agent.analyze_email_simple(email_content)
            print(f"\n🎯 CLASIFICACIÓN: {classification.upper()}")
            
            if args.output_file:
                simple_result = {"classification": classification}
                save_result_to_file(simple_result, args.output_file)
                
        else:
            # Análisis completo
            result = await agent.analyze_email(email_content)
            
            # Mostrar reporte legible
            report = await agent.get_detailed_report(email_content)
            print(report)
            
            # Guardar en archivo si se especifica
            if args.output_file:
                save_result_to_file(result, args.output_file)
            
        return 0
        
    except Exception as e:
        logger.error(f"Error durante el análisis: {e}")
        print(f"❌ Error: {e}")
        return 1


def main():
    parser = argparse.ArgumentParser(
        description="Detector multimodal de phishing bancario en correos electrónicos"
    )
    parser.add_argument(
        "--email-file",
        type=Path,
        required=True,
        help="Ruta al archivo de correo electrónico en texto plano a analizar.",
    )
    parser.add_argument(
        "--output-file",
        type=Path,
        help="Archivo donde guardar el resultado en formato JSON (opcional).",
    )
    parser.add_argument(
        "--verbose", "-v",
        action="store_true",
        help="Mostrar información detallada del procesamiento.",
    )
    parser.add_argument(
        "--simple",
        action="store_true",
        help="Mostrar solo la clasificación básica (phishing/legitimate/suspicious).",
    )
    
    args = parser.parse_args()
    
    setup_logging(args.verbose)

    # Validar que el archivo existe
    if not args.email_file.exists():
        print(f"❌ Error: El archivo {args.email_file} no existe.")
        return 1

    # Ejecutar análisis asíncrono
    return asyncio.run(analyze_email(args))


if __name__ == "__main__":
    exit(main()) 