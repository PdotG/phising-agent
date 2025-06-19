# 🚀 Funcionalidades Mejoradas del Detector de Phishing

## Nuevas Capacidades Implementadas

### 1. 🛡️ Threat Intelligence Dinámico

#### ¿Qué hace?
- **Descarga automática** de dominios maliciosos de múltiples fuentes
- **Cache inteligente** para optimizar rendimiento
- **Verificación en tiempo real** contra bases de datos de amenazas

#### Fuentes por Defecto:
- **PhishTank**: Base de datos colaborativa de phishing (requiere API key)
- **OpenPhish**: Feed gratuito de URLs de phishing
- **Abuse.ch URLhaus**: Malware URLs
- **Malware Domain List**: Dominios maliciosos conocidos

#### Configuración:
```env
# Archivo .env
PHISHTANK_API_KEY="tu_api_key_aqui"  # Opcional pero recomendado
```

#### Uso Programático:
```python
from app.data_sources.threat_intelligence import ThreatIntelligenceManager

# Configurar con fuentes personalizadas
config = {
    "phishtank_api_key": "your_key",
    "custom_threat_sources": [
        {
            "name": "mi_lista_personalizada",
            "url": "https://mi-empresa.com/dominios-maliciosos.txt",
            "update_frequency": 3600  # 1 hora
        }
    ]
}

threat_intel = ThreatIntelligenceManager(config)

# Verificar un dominio
result = await threat_intel.check_domain("evil-bank.com")
print(f"¿Es malicioso? {result['is_malicious']}")

# Añadir nueva fuente dinámicamente
threat_intel.add_custom_source(
    "nueva_fuente", 
    "https://otra-fuente.com/blacklist.txt"
)
```

#### Ejemplo de Resultado:
```json
{
  "domain": "fake-bank.com",
  "is_malicious": true,
  "exact_match": true,
  "parent_match": false,
  "total_sources": 4,
  "timestamp": "2024-01-15T10:30:00"
}
```

---

### 2. 📎 Análisis Avanzado de Attachments

#### ¿Qué hace?
- **Detección de malware** por extensión y tipo MIME
- **Análisis de firmas** de archivo (magic numbers)
- **Escaneado de archivos comprimidos** (ZIP, RAR, 7Z)
- **Detección de doble extensión** y otros trucos
- **Búsqueda de patrones maliciosos** en texto

#### Tipos de Amenazas Detectadas:
- **Ejecutables**: .exe, .bat, .cmd, .scr, .vbs
- **Scripts**: .js, .ps1, .vbe, .wsf
- **Archivos con macros**: .docm, .xlsm, .pptm
- **Archivos comprimidos** con contenido peligroso
- **Firmas falsificadas** (archivo .pdf que es realmente .exe)

#### Uso:
```python
from app.tools.attachment_analyzer import AttachmentAnalyzer

analyzer = AttachmentAnalyzer({
    "max_file_size": 50 * 1024 * 1024,  # 50MB
    "scan_archives": True
})

# Analizar email completo
analysis = analyzer.analyze_email_attachments(email_content)

print(f"Attachments peligrosos: {analysis['has_dangerous']}")
print(f"Riesgo general: {analysis['risk_score']*100:.1f}%")

# Resumen legible
summary = analyzer.get_attachment_summary(analysis)
print(summary)
```

#### Ejemplo de Detección:
```
📎 2 attachment(s) encontrado(s)
⚠️ ATTACHMENTS PELIGROSOS DETECTADOS:
  • documento.pdf.exe (245760 bytes) - 🔴 PELIGROSO
    - Extensión peligrosa: .exe
    - Posible doble extensión
    - Firma de archivo no coincide con extensión
  • informe.docx (89432 bytes) - ✅ Seguro

🎯 Riesgo general: 85.0%
```

---

### 3. 🌐 Búsqueda Web Inteligente

#### ¿Qué hace?
- **Verifica reputación** de dominios en internet
- **Busca antecedentes** de phishing/malware
- **Analiza contenido** del email contra campañas conocidas
- **Encuentra reportes** de seguridad existentes

#### Motores de Búsqueda Soportados:
- **Brave Search** (recomendado - privacidad + API oficial)
- **DuckDuckGo** (backup - sin API key requerida)

#### Configuración:
```env
# Archivo .env
BRAVE_API_KEY="tu_api_key_de_brave"  # Obtener en https://api.search.brave.com/
```

#### Uso:
```python
from app.tools.web_intelligence import WebIntelligenceSearcher

searcher = WebIntelligenceSearcher({
    "brave_api_key": "your_key",
    "max_search_results": 5
})

# Verificar reputación de dominio
reputation = await searcher.search_domain_reputation("suspicious-bank.com")
print(f"Puntuación de reputación: {reputation['reputation_score']*100:.1f}%")

# Buscar inteligencia de contenido
content_intel = await searcher.search_email_content_intelligence(email_content)
print(f"Elementos analizados: {len(content_intel['elements_searched'])}")
```

#### Ejemplo de Búsqueda:
```
🌐 INTELIGENCIA WEB
==============================

🔴 DOMINIO CON MALA REPUTACIÓN
📊 Puntuación de reputación: 85.0%
🔍 Resultados encontrados: 12

⚠️ REPORTES DE PHISHING:
  • phishing: "Evil-bank.com reported as phishing site"
  • scam: "Fraudulent banking site evil-bank.com blocked"

🛡️ ADVERTENCIAS DE SEGURIDAD:
  • virustotal.com: "evil-bank.com detected as malicious"
  • phishtank.com: "Phishing URL reported by users"
```

---

## 🔄 Agente Mejorado Integrado

### Uso del Enhanced Agent

```python
from app.agent.enhanced_multimodal_agent import EnhancedMultimodalPhishingAgent
from config import get_enhanced_agent_config

# Crear agente con configuración completa
agent = EnhancedMultimodalPhishingAgent(get_enhanced_agent_config())

# Análisis completo
result = await agent.analyze_email_comprehensive(
    email_content=email_text,
    images=email_images,
    perform_web_search=True,      # Habilitar búsqueda web
    check_threat_intel=True       # Habilitar threat intelligence
)

# Reporte legible completo
report = await agent.get_enhanced_report(
    email_content=email_text,
    images=email_images
)
print(report)
```

### Ejemplo de Reporte Completo:

```
🛡️ ANÁLISIS COMPLETO DE PHISHING
==================================================

🎯 CLASIFICACIÓN FINAL: PHISHING
📊 CONFIANZA: 94.5%
⚠️ NIVEL DE RIESGO: HIGH
🔍 FUENTES CONSULTADAS: multimodal_llm, attachment_scanner, threat_intelligence, web_search

📧 ANÁLISIS MULTIMODAL:
   • Clasificación LLM: phishing
   • Idioma detectado: es
   • Modelo usado: gpt-4-vision-preview

📎 2 attachment(s) encontrado(s)
⚠️ ATTACHMENTS PELIGROSOS DETECTADOS:
  • malware.exe (245760 bytes) - 🔴 PELIGROSO
    - Extensión peligrosa: .exe
    - Tipo MIME peligroso: application/x-executable

🔍 THREAT INTELLIGENCE:
   • Dominios verificados: 3
   • Dominios maliciosos: 2
   • Fuentes consultadas: 4

⚠️ DOMINIOS MALICIOSOS DETECTADOS:
   • evil-bank.com
   • fake-security.net

🌐 INTELIGENCIA WEB
==============================
🔴 DOMINIO CON MALA REPUTACIÓN
📊 Puntuación de reputación: 85.0%
🔍 Resultados encontrados: 12

💡 RECOMENDACIÓN FINAL:
🚨 PHISHING CONFIRMADO
• NO hacer clic en ningún enlace
• NO proporcionar información personal
• Eliminar el email inmediatamente
• ATTACHMENTS PELIGROSOS DETECTADOS - No abrir
• Dominios maliciosos conocidos detectados

📊 Confianza del análisis: 94.5%
🔍 Fuentes consultadas: 4
```

---

## ⚙️ Configuración Avanzada

### Variables de Entorno Necesarias:

```env
# LLM (requerido)
OPENAI_API_KEY="tu_clave_openai"
MODEL_NAME="gpt-4-vision-preview"

# Threat Intelligence (opcional pero recomendado)
PHISHTANK_API_KEY="tu_clave_phishtank"

# Web Search (opcional pero recomendado)
BRAVE_API_KEY="tu_clave_brave"

# Configuración general
LOG_LEVEL="INFO"
ENVIRONMENT="development"
```

### Configuración por Código:

```python
config = {
    "threat_intelligence": {
        "phishtank_api_key": "your_key",
        "custom_threat_sources": [
            {
                "name": "empresa_blacklist",
                "url": "https://tu-empresa.com/blacklist.txt",
                "update_frequency": 1800
            }
        ]
    },
    "attachment_analysis": {
        "max_file_size": 100 * 1024 * 1024,  # 100MB
        "scan_archives": True,
        "detailed_analysis": True
    },
    "web_search": {
        "brave_api_key": "your_brave_key",
        "max_search_results": 10,
        "enable_content_intelligence": True
    }
}

agent = EnhancedMultimodalPhishingAgent(config)
```

---

## 🚀 Nuevas Funcionalidades en CLI

### Comandos Actualizados:

```bash
# Análisis básico (sin nuevas funcionalidades)
python -m app.main --email-file email.txt

# Análisis completo con todas las funcionalidades
python -m app.main --email-file email.txt --enhanced --web-search --threat-intel

# Solo threat intelligence
python -m app.main --email-file email.txt --threat-intel-only

# Solo análisis de attachments
python -m app.main --email-file email.txt --attachments-only

# Modo verbose con detalles
python -m app.main --email-file email.txt --enhanced --verbose
```

---

## 📊 Beneficios de las Nuevas Funcionalidades

### 1. **Mayor Precisión**
- **Reducción de falsos positivos**: Múltiples fuentes de verificación
- **Detección temprana**: Threat intelligence actualizada
- **Análisis holístico**: Texto + imágenes + attachments + reputación

### 2. **Detección Avanzada**
- **Campañas conocidas**: Búsqueda de antecedentes
- **Malware en attachments**: Análisis profundo de archivos
- **Dominios emergentes**: Verificación contra listas actualizadas

### 3. **Inteligencia Contextual**
- **Reputación web**: Información de múltiples fuentes
- **Patrones de ataque**: Reconocimiento de técnicas conocidas
- **Evidencia múltiple**: Mayor confianza en resultados

### 4. **Flexibilidad**
- **Fuentes personalizables**: Añadir tus propias listas
- **Configuración granular**: Activar/desactivar módulos
- **Escalabilidad**: Cache y optimizaciones incluidas

---

## ⚠️ Consideraciones de Seguridad

### Datos Enviados a APIs Externas:
- **Dominios**: Se envían a fuentes de threat intelligence
- **Queries de búsqueda**: Se envían a motores de búsqueda
- **Hashes**: Solo hashes, nunca contenido completo

### Recomendaciones:
- Usar **Brave Search** en lugar de Google (mayor privacidad)
- Configurar **cache local** para reducir consultas externas
- **Revisar logs** para entender qué datos se envían
- **Evaluar políticas** de cada proveedor de threat intelligence

---

## 🔧 Troubleshooting

### Problemas Comunes:

#### "Import magic could not be resolved"
```bash
# Instalar python-magic
pip install python-magic

# En sistemas Linux también:
sudo apt-get install libmagic1

# En macOS:
brew install libmagic
```

#### "No se pueden descargar dominios maliciosos"
- Verificar conectividad a internet
- Comprobar si las URLs de fuentes están activas
- Revisar logs para errores específicos

#### "Brave Search no funciona"
- Verificar API key válida
- Comprobar límites de rate limiting
- Usar DuckDuckGo como backup

#### "Análisis muy lento"
- Deshabilitar web search: `perform_web_search=False`
- Reducir `max_search_results`
- Aumentar `cache_duration` en configuración

---

## 🎯 Próximas Mejoras Planificadas

1. **Análisis de Headers de Email**: Verificación SPF/DKIM/DMARC
2. **Machine Learning Local**: Modelo entrenado localmente
3. **Integración con MISP**: Threat intelligence empresarial
4. **Sandbox Analysis**: Ejecución segura de attachments
5. **API de Reputación IP**: Verificación de IPs de origen 