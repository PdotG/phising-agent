"""Script para ejecutar la API y la interfaz de usuario."""

import subprocess
import sys
import time
import webbrowser
from pathlib import Path
import os

def run_api():
    """Ejecuta la API FastAPI."""
    subprocess.Popen([
        sys.executable, "-m", "uvicorn",
        "app.api:app", "--host", "0.0.0.0", "--port", "8000"
    ])

def run_streamlit():
    """Ejecuta la interfaz Streamlit."""
    subprocess.Popen([
        sys.executable, "-m", "streamlit", "run",
        "app/streamlit_app.py",
        "--server.port", "8501",
        "--browser.serverAddress", "localhost"
    ])

def main():
    # Asegurar que estamos en el directorio correcto
    project_root = Path(__file__).parent
    if project_root.name == "phishing_detector":
        os.chdir(project_root)
    
    print("🚀 Iniciando Detector de Phishing...")
    
    # Iniciar API
    print("📡 Iniciando API REST...")
    run_api()
    time.sleep(2)  # Esperar a que la API esté lista
    
    # Iniciar Streamlit
    print("🌐 Iniciando interfaz web...")
    run_streamlit()
    time.sleep(2)  # Esperar a que Streamlit esté listo
    
    # Abrir navegador
    print("🔗 Abriendo interfaz en el navegador...")
    webbrowser.open("http://localhost:8501")
    
    print("""
✨ ¡Sistema iniciado correctamente!

📌 URLs importantes:
   • Interfaz web: http://localhost:8501
   • API REST: http://localhost:8000
   • Documentación API: http://localhost:8000/docs

🛑 Para detener el sistema, presiona Ctrl+C
    """)
    
    try:
        # Mantener el script corriendo
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        print("\n👋 Deteniendo el sistema...")
        sys.exit(0)

if __name__ == "__main__":
    main() 