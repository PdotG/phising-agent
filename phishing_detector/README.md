# 🛡️ Phishing Detector Multimodal

Detector de phishing bancario que aprovecha las **capacidades multimodales de LLMs avanzados** para analizar texto e imágenes simultáneamente, con **threat intelligence en tiempo real**, **análisis de attachments** y **búsqueda web inteligente**.

## 🚀 Características

- **🧠 Análisis multimodal**: El LLM analiza texto + imágenes en una sola pasada
- **🛡️ Threat Intelligence**: Descarga automática de dominios maliciosos de múltiples fuentes
- **📎 Análisis de attachments**: Detección avanzada de malware y archivos peligrosos
- **🌐 Búsqueda web inteligente**: Verificación de reputación y antecedentes online
- **🏦 Especializado en bancos españoles**: Conoce logos y dominios oficiales
- **🎯 Detección inteligente**: Identifica logos falsos, dominios sospechosos y patrones de phishing
- **⚡ Simple y directo**: Sin infraestructura compleja, solo el poder del LLM
- **📊 Reportes detallados**: Análisis estructurado con niveles de confianza
- **🔧 Múltiples interfaces**: CLI, API REST, interfaz web

## 🧠 Cómo Funciona

A diferencia de sistemas tradicionales que usan múltiples herramientas, este detector:

1. **Extrae automáticamente** las imágenes embebidas del email
2. **Envía texto + imágenes** al LLM multimodal 
3. **El LLM analiza todo junto** detectando inconsistencias visuales y textuales
4. **Devuelve análisis estructurado** en JSON con recomendaciones claras

## 📋 Requisitos

- Python 3.9+
- API key de un LLM con capacidades multimodales:
  - **GPT-4 Vision** (OpenAI)
  - **GPT-4o** (OpenAI) 
  - **Claude 3** (Anthropic)
  - Cualquier modelo compatible con formato OpenAI

## 📋 Instalación

### 1. Clonar Repositorio
```bash
git clone <repo-url>
cd phishing_detector
```

### 2. Crear Entorno Virtual (Recomendado)
```bash
python -m venv venv
source venv/bin/activate  # Linux/Mac
# o
venv\Scripts\activate     # Windows
```

### 3. Instalar Dependencias
```bash
pip install -r requirements.txt
```

### 4. Configurar Variables de Entorno
Crear archivo `.env` en la raíz del proyecto:

```env
# === REQUERIDO ===
OPENAI_API_KEY="tu_clave_openai_aqui"

# === OPCIONAL PERO RECOMENDADO ===
# Para modelos específicos
MODEL_NAME="gpt-4-vision-preview"  # o "gpt-4o"
OPENAI_API_BASE="https://api.openai.com/v1"

# Para threat intelligence mejorado
PHISHTANK_API_KEY="tu_clave_phishtank"

# Para búsqueda web inteligente
BRAVE_API_KEY="tu_clave_brave"

# === CONFIGURACIÓN GENERAL ===
LOG_LEVEL="INFO"
ENVIRONMENT="development"
```

### 5. Verificar Instalación
```bash
python -m app.main --email-file data/example_phishing_email.txt
```

---

## ⚡ Inicio Rápido

**¿Primera vez? Las opciones más comunes:**

```bash
# 🎯 MÁS SIMPLE: Solo interfaz web
python -m streamlit run app/streamlit_app.py
# Luego ve a: http://localhost:8501

# 🚀 COMPLETO: API + Web (si run.py funciona)
python run.py

# 💻 LÍNEA DE COMANDOS: Para scripts y automatización  
python -m app.main --email-file data/example_phishing_email.txt

# 🔧 SOLO API: Para integraciones
python -m uvicorn app.api:app --host 0.0.0.0 --port 8000
```

---

## 🚀 Opciones de Lanzamiento Detalladas

### **1. 🌐 Interfaz Web Completa (Recomendado)**
**Inicia API + Interfaz Web + Abre navegador automáticamente**

```bash
cd phishing_detector
python run.py
```

**Servicios disponibles:**
- 🖥️ **Interfaz Web**: `http://localhost:8501`
- 🔧 **API REST**: `http://localhost:8000`
- 📚 **Documentación API**: `http://localhost:8000/docs`

**Características:**
- ✅ Upload de emails y attachments
- ✅ Visualización interactiva de resultados
- ✅ Análisis por tabs (Texto, Imágenes, Dominios, Attachments)
- ✅ Exportación de resultados

---

### **2. 📱 Solo Interfaz Web (Streamlit)**
**Para desarrollo o uso personal**

```bash
cd phishing_detector
python -m streamlit run app/streamlit_app.py
```

**Acceso:** `http://localhost:8501`

**Ventajas:**
- 🎨 Interfaz amigable y visual
- 📤 Upload directo de archivos
- 📊 Gráficos y métricas en tiempo real
- 🔄 Análisis interactivo

---

### **3. 🔧 Solo API REST (FastAPI)**
**Para integraciones y desarrollo de aplicaciones**

```bash
cd phishing_detector
python -m uvicorn app.api:app --host 0.0.0.0 --port 8000 --reload
```

**Endpoints principales:**
- `POST /analyze/` - Análisis completo
- `POST /analyze/file/` - Upload de archivos
- `GET /health` - Estado del sistema
- `GET /docs` - Documentación interactiva

**Ejemplo de uso:**
```bash
curl -X POST "http://localhost:8000/analyze/" \
     -H "Content-Type: application/json" \
     -d '{"text": "Email sospechoso aquí", "images": []}'
```

---

### **4. 💻 Línea de Comandos (CLI)**
**Para automatización y análisis por lotes**

#### Análisis Básico
```bash
cd phishing_detector
python -m app.main --email-file data/example_phishing_email.txt
```

#### Análisis Completo con Todas las Funcionalidades
```bash
python -m app.main --email-file data/example_phishing_email.txt --enhanced
```

#### Solo Clasificación
```bash
python -m app.main --email-file data/example_phishing_email.txt --simple
```

#### Guardar Resultado en JSON
```bash
python -m app.main --email-file data/example_phishing_email.txt --output-file resultado.json
```

#### Modo Verbose (Debugging)
```bash
python -m app.main --email-file data/example_phishing_email.txt --verbose
```

#### Opciones Específicas
```bash
# Solo threat intelligence
python -m app.main --email-file email.txt --threat-intel-only

# Solo análisis de attachments
python -m app.main --email-file email.txt --attachments-only

# Sin búsqueda web (más rápido)
python -m app.main --email-file email.txt --no-web-search
```

---

### **5. 🐍 Uso Programático**
**Para integración en otros proyectos Python**

#### Análisis Básico
```python
import asyncio
from app.agent.multimodal_phishing_agent import MultimodalPhishingAgent

async def analyze_basic():
    agent = MultimodalPhishingAgent()
    
    with open('email.txt', 'r') as f:
        email_content = f.read()
    
    result = await agent.analyze_email(email_content)
    print(f"Clasificación: {result.get('classification')}")

asyncio.run(analyze_basic())
```

#### Análisis Completo con Todas las Funcionalidades
```python
import asyncio
from app.agent.enhanced_multimodal_agent import EnhancedMultimodalPhishingAgent

async def analyze_enhanced():
    agent = EnhancedMultimodalPhishingAgent()
    
    with open('email.txt', 'r') as f:
        email_content = f.read()
    
    # Análisis completo
    result = await agent.analyze_email_comprehensive(
        email_content=email_content,
        perform_web_search=True,
        check_threat_intel=True
    )
    
    print(f"Clasificación: {result['enhanced_classification']}")
    print(f"Confianza: {result['confidence']*100:.1f}%")
    print(f"Fuentes: {result['sources_used']}")
    
    # Reporte legible
    report = await agent.get_enhanced_report(email_content)
    print(report)

asyncio.run(analyze_enhanced())
```

#### Configuración Personalizada
```python
config = {
    "threat_intelligence": {
        "custom_threat_sources": [
            {
                "name": "mi_empresa",
                "url": "https://mi-empresa.com/blacklist.txt",
                "update_frequency": 1800
            }
        ]
    },
    "web_search": {
        "brave_api_key": "tu_key",
        "max_search_results": 10
    }
}

agent = EnhancedMultimodalPhishingAgent(config)
```

---

## 🔧 Solución de Problemas

### **Error: "OPENAI_API_KEY environment variable"**
```bash
# Solución 1: Crear archivo .env
echo 'OPENAI_API_KEY="tu_clave_aqui"' > .env

# Solución 2: Exportar variable
export OPENAI_API_KEY="tu_clave_aqui"

# Solución 3: Pasar en tiempo de ejecución
OPENAI_API_KEY="tu_clave" python -m app.main --email-file email.txt
```

### **Error: "Import magic could not be resolved"**
```bash
# En Linux/Ubuntu
sudo apt-get install libmagic1
pip install python-magic

# En macOS
brew install libmagic
pip install python-magic

# En Windows
pip install python-magic-bin
```

### **Error: "FileNotFoundError" en run.py**
```bash
# Verificar que estás en el directorio correcto
cd phishing_detector
pwd  # Debe mostrar .../phishing_detector

# Si run.py da problemas, ejecutar servicios individualmente:

# Terminal 1: API REST
python -m uvicorn app.api:app --host 0.0.0.0 --port 8000 --reload

# Terminal 2: Interfaz Web  
python -m streamlit run app/streamlit_app.py --server.port 8501

# O usar alternativas más simples:
# Solo Streamlit (más común)
python -m streamlit run app/streamlit_app.py

# Solo CLI (sin interfaz web)
python -m app.main --email-file data/example_phishing_email.txt
```

### **Error: "AppImage" o archivos no encontrados**
```bash
# Si aparecen errores relacionados con Cursor o AppImage:
# Esto suele ser un problema de configuración del editor, no del código

# Solución 1: Limpiar variables de entorno
unset EDITOR
unset VISUAL

# Solución 2: Ejecutar desde terminal limpio
bash --noprofile --norc
cd /ruta/completa/a/phishing_detector
python run.py

# Solución 3: Usar métodos alternativos (recomendado)
python -m streamlit run app/streamlit_app.py
```

### **Puertos Ocupados**
```bash
# Verificar puertos en uso
lsof -i :8000  # API
lsof -i :8501  # Streamlit

# Matar procesos si es necesario
kill -9 $(lsof -t -i:8000)
kill -9 $(lsof -t -i:8501)

# Usar puertos alternativos
python -m uvicorn app.api:app --port 8080
python -m streamlit run app/streamlit_app.py --server.port 8502
```

### **Problema con Dependencias**
```bash
# Reinstalar todo limpio
pip uninstall -y -r requirements.txt
pip install -r requirements.txt

# O crear entorno nuevo
python -m venv venv_nuevo
source venv_nuevo/bin/activate
pip install -r requirements.txt
```

---

## 📊 Ejemplos de Uso

### **Análisis de Email con Attachments**
```bash
python -m app.main --email-file email_con_attachments.eml --enhanced
```

### **Análisis por Lotes**
```bash
for email in emails/*.txt; do
    python -m app.main --email-file "$email" --output-file "results/$(basename $email .txt).json"
done
```

### **Servidor de Producción**
```bash
python -m uvicorn app.api:app --host 0.0.0.0 --port 8000 --workers 4
```

---

## 🎯 APIs Externas (Opcionales)

### **OpenAI (Requerido)**
- **Obtener**: https://platform.openai.com/api-keys
- **Costo**: ~$0.01-0.03 por análisis
- **Variable**: `OPENAI_API_KEY`

### **PhishTank (Recomendado)**
- **Obtener**: https://www.phishtank.com/api_info.php
- **Costo**: Gratuito
- **Variable**: `PHISHTANK_API_KEY`

### **Brave Search (Recomendado)**
- **Obtener**: https://api.search.brave.com/
- **Costo**: Gratuito hasta 2000 queries/mes
- **Variable**: `BRAVE_API_KEY`

---

## 🚀 Modo de Desarrollo

```bash
# Con recarga automática
python -m uvicorn app.api:app --reload
python -m streamlit run app/streamlit_app.py

# Con debugging
LOG_LEVEL=DEBUG python -m app.main --email-file email.txt --verbose

# Ejecutar tests (si existen)
python -m pytest tests/
```

---

## 📁 Estructura del Proyecto

```
phishing_detector/
├── run.py                 # Lanzador principal
├── requirements.txt       # Dependencias
├── .env                   # Variables de entorno
├── README.md             # Esta documentación
├── ENHANCED_FEATURES.md  # Funcionalidades avanzadas
├── app/
│   ├── main.py           # CLI principal
│   ├── api.py            # API REST
│   ├── streamlit_app.py  # Interfaz web
│   ├── agent/            # Agentes de análisis
│   ├── tools/            # Herramientas especializadas
│   ├── data_sources/     # Fuentes de threat intelligence
│   └── utils/            # Utilidades
├── data/
│   ├── example_*.txt     # Emails de ejemplo
│   └── cache/            # Cache de threat intelligence
└── config.py             # Configuración central
```

---

## 💡 Recomendaciones de Uso

### **Para Empezar**
1. **Usar interfaz web**: `python run.py`
2. **Probar con ejemplos**: Usar archivos en `data/`
3. **Verificar APIs**: Comprobar que las claves funcionen

### **Para Producción**
1. **Configurar APIs externas** para máxima precisión
2. **Usar worker múltiples** en uvicorn
3. **Monitorizar logs** para detectar problemas
4. **Configurar cache** para optimizar rendimiento

### **Para Desarrollo**
1. **Modo verbose** para debugging
2. **API reload** para cambios en caliente
3. **Tests unitarios** para validar cambios 