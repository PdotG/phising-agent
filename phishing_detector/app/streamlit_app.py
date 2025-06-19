"""Interfaz de usuario avanzada con Streamlit para el detector de phishing."""

import streamlit as st
import requests
import json
import os
from typing import Dict, Any, List, Optional
import base64
from PIL import Image
import io
import time
import traceback
from datetime import datetime

# Configuración de la página
st.set_page_config(
    page_title="🛡️ Detector de Phishing Avanzado",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded"
)

# Estilos CSS mejorados
st.markdown("""
<style>
    .main { padding: 1rem 2rem; }
    
    .risk-critical {
        background: linear-gradient(90deg, #ff4757, #ff3838);
        color: white; padding: 15px; border-radius: 10px;
        text-align: center; font-weight: bold; font-size: 1.1em;
        margin: 10px 0;
    }
    
    .risk-high {
        background: linear-gradient(90deg, #ff6b6b, #ee5a52);
        color: white; padding: 15px; border-radius: 10px;
        text-align: center; font-weight: bold; margin: 10px 0;
    }
    
    .risk-medium {
        background: linear-gradient(90deg, #ffa726, #ff9800);
        color: white; padding: 15px; border-radius: 10px;
        text-align: center; font-weight: bold; margin: 10px 0;
    }
    
    .risk-low {
        background: linear-gradient(90deg, #66bb6a, #4caf50);
        color: white; padding: 15px; border-radius: 10px;
        text-align: center; font-weight: bold; margin: 10px 0;
    }
    
    .metric-card {
        background: #f8f9fa; padding: 1.5rem; border-radius: 15px;
        border-left: 5px solid #007bff; margin: 0.5rem 0;
        box-shadow: 0 2px 10px rgba(0,0,0,0.1);
    }
    
    .status-connected {
        background: #d4edda; color: #155724;
        padding: 0.5rem 1rem; border-radius: 20px; font-weight: bold;
    }
    
    .status-disconnected {
        background: #f8d7da; color: #721c24;
        padding: 0.5rem 1rem; border-radius: 20px; font-weight: bold;
    }
    
    .stButton > button {
        background: linear-gradient(90deg, #667eea 0%, #764ba2 100%);
        color: white; border: none; border-radius: 10px;
        padding: 0.75rem 2rem; font-weight: bold;
        transition: all 0.3s ease;
    }
    
    .stButton > button:hover {
        transform: translateY(-2px);
        box-shadow: 0 5px 15px rgba(0,0,0,0.2);
    }
    
    .error-container {
        background: #fee; border: 2px solid #f88;
        border-radius: 10px; padding: 1rem; margin: 1rem 0;
    }
    
    .success-container {
        background: #efe; border: 2px solid #8f8;
        border-radius: 10px; padding: 1rem; margin: 1rem 0;
    }
</style>
""", unsafe_allow_html=True)

# Inicializar estado de sesión
if 'analysis_history' not in st.session_state:
    st.session_state.analysis_history = []
if 'api_config' not in st.session_state:
    st.session_state.api_config = {
        'base_url': 'http://localhost:8000',
        'timeout': 60,
        'use_enhanced': True
    }

def check_api_connection() -> Dict[str, Any]:
    """Verifica la conexión con la API."""
    try:
        response = requests.get(
            f"{st.session_state.api_config['base_url']}/health",
            timeout=5
        )
        if response.status_code == 200:
            return {'status': 'connected', 'message': 'API disponible'}
        else:
            return {'status': 'error', 'message': f'Error {response.status_code}'}
    except requests.exceptions.ConnectionError:
        return {
            'status': 'disconnected',
            'message': 'No se puede conectar con la API'
        }
    except Exception as e:
        return {'status': 'error', 'message': f'Error: {str(e)}'}

def image_to_base64(image_file) -> str:
    """Convierte una imagen a base64."""
    try:
        return base64.b64encode(image_file.getvalue()).decode()
    except Exception as e:
        st.error(f"Error procesando imagen: {str(e)}")
        return ""

def display_enhanced_analysis_result(result: Dict[str, Any]):
    """Muestra el resultado del análisis de forma avanzada."""
    try:
        st.markdown("## 📊 Resultado del Análisis")
        
        # Métricas principales
        col1, col2, col3, col4 = st.columns(4)
        
        with col1:
            classification = result.get("classification", "Desconocido")
            class_emoji = {
                "PHISHING": "🚨",
                "SOSPECHOSO": "⚠️", 
                "LEGÍTIMO": "✅",
                "SPAM": "📧"
            }.get(classification.upper(), "❓")
            
            st.metric("Clasificación", f"{class_emoji} {classification}")
        
        with col2:
            confidence = result.get("confidence", 0)
            st.metric("Confianza", f"{confidence*100:.1f}%")
        
        with col3:
            risk_level = result.get("risk_level", "unknown")
            risk_emoji = {
                "low": "🟢", "medium": "🟡", "high": "🔴", "critical": "⚫"
            }.get(risk_level, "⚪")
            st.metric("Riesgo", f"{risk_emoji} {risk_level.title()}")
        
        with col4:
            sources = result.get('sources_used', [])
            sources_count = len(sources) if sources else 1
            st.metric("Fuentes", f"🔍 {sources_count}")
        
        # Análisis detallado en tabs
        tab1, tab2, tab3, tab4, tab5 = st.tabs([
            "📝 Texto", "🖼️ Imágenes", "🌐 Dominios", "📎 Attachments", "🔍 Web"
        ])
        
        with tab1:
            st.subheader("📝 Análisis de Texto")
            text_analysis = result.get("text_analysis", {})
            
            col1, col2, col3, col4 = st.columns(4)
            with col1:
                patterns_count = len(text_analysis.get("suspicious_patterns", []))
                st.metric("Patrones Sospechosos", patterns_count)
            with col2:
                urgency = "✅" if text_analysis.get("urgency_language") else "❌"
                st.metric("Lenguaje Urgente", urgency)
            with col3:
                personal_data = "✅" if text_analysis.get("requests_personal_data") else "❌"
                st.metric("Solicita Datos", personal_data)
            with col4:
                spelling = "✅" if text_analysis.get("spelling_errors") else "❌"
                st.metric("Errores Texto", spelling)
            
            if text_analysis.get("suspicious_patterns"):
                st.write("**Patrones detectados:**")
                for pattern in text_analysis["suspicious_patterns"]:
                    st.write(f"• {pattern}")
        
        with tab2:
            st.subheader("🖼️ Análisis de Imágenes")
            img_analysis = result.get("image_analysis", {})
            
            col1, col2, col3 = st.columns(3)
            with col1:
                st.metric("Imágenes", img_analysis.get("images_analyzed", 0))
            with col2:
                suspicious = "✅" if img_analysis.get("suspicious_logos") else "❌"
                st.metric("Logos Sospechosos", suspicious)
            with col3:
                quality = "✅" if img_analysis.get("logo_quality_issues") else "❌"
                st.metric("Problemas Calidad", quality)
            
            if img_analysis.get("details"):
                st.write("**Detalles:**")
                st.write(img_analysis["details"])
        
        with tab3:
            st.subheader("🌐 Análisis de Dominios")
            domain_analysis = result.get("domain_analysis", {})
            
            domains_found = domain_analysis.get("domains_found", [])
            suspicious_domains = domain_analysis.get("suspicious_domains", [])
            official_domains = domain_analysis.get("official_domains", [])
            
            if domains_found:
                st.write("**Dominios encontrados:**")
                for domain in domains_found:
                    if domain in suspicious_domains:
                        st.markdown(f"🔴 `{domain}` (SOSPECHOSO)")
                    elif domain in official_domains:
                        st.markdown(f"🟢 `{domain}` (OFICIAL)")
                    else:
                        st.markdown(f"🟡 `{domain}` (NEUTRO)")
            
            # Threat Intelligence
            threat_intel = result.get("threat_intelligence", {})
            if threat_intel:
                if threat_intel.get("is_malicious"):
                    st.error("⚠️ Dominio en listas de amenazas")
                else:
                    st.success("✅ Dominio limpio")
        
        with tab4:
            st.subheader("📎 Análisis de Attachments")
            attachment_analysis = result.get("attachment_analysis", {})
            
            if attachment_analysis and attachment_analysis.get("total_attachments", 0) > 0:
                col1, col2, col3 = st.columns(3)
                with col1:
                    st.metric("Total", attachment_analysis.get("total_attachments", 0))
                with col2:
                    dangerous = "✅" if attachment_analysis.get("has_dangerous") else "❌"
                    st.metric("Peligrosos", dangerous)
                with col3:
                    risk_score = attachment_analysis.get('risk_score', 0) * 100
                    st.metric("Riesgo", f"{risk_score:.1f}%")
                
                # Detalles de attachments
                attachments = attachment_analysis.get("attachments", [])
                for i, att in enumerate(attachments):
                    with st.expander(f"📄 {att.get('filename', f'Archivo {i+1}')}"):
                        analysis = att.get('analysis', {})
                        st.write(f"**Tamaño:** {att.get('size', 0)} bytes")
                        st.write(f"**Tipo:** {analysis.get('mime_type', 'Desconocido')}")
                        is_dangerous = "🔴 SÍ" if analysis.get('is_dangerous') else "🟢 NO"
                        st.write(f"**Peligroso:** {is_dangerous}")
                        
                        threats = analysis.get('threats', [])
                        if threats:
                            st.write("**Amenazas:**")
                            for threat in threats:
                                st.write(f"• {threat}")
            else:
                st.info("📭 Sin archivos adjuntos")
        
        with tab5:
            st.subheader("🔍 Búsqueda Web")
            web_intelligence = result.get("web_intelligence", {})
            
            if web_intelligence:
                # Reputación de dominios
                reputation = web_intelligence.get("domain_reputation", {})
                if reputation:
                    st.write("**🌐 Reputación:**")
                    for domain, rep_data in reputation.items():
                        score = rep_data.get("reputation_score", 0)
                        color = "🟢" if score > 0.7 else "🟡" if score > 0.3 else "🔴"
                        st.write(f"{color} `{domain}`: {score*100:.1f}%")
                
                # Búsqueda de antecedentes
                background = web_intelligence.get("background_search", {})
                if background and background.get("results"):
                    st.write("**🔍 Búsqueda:**")
                    for item in background["results"][:3]:
                        title = item.get('title', 'Sin título')
                        url = item.get('url', '#')
                        st.write(f"• [{title}]({url})")
            else:
                st.info("🔍 Sin búsqueda web")
        
        # Recomendación final
        st.markdown("---")
        recommendation = result.get("recommendation", "Sin recomendación")
        
        if risk_level in ['high', 'critical']:
            st.markdown(f"""
            <div class="risk-high">
                <h3>⚠️ RECOMENDACIÓN CRÍTICA</h3>
                <p>{recommendation}</p>
            </div>
            """, unsafe_allow_html=True)
        elif risk_level == 'medium':
            st.markdown(f"""
            <div class="risk-medium">
                <h3>⚠️ PRECAUCIÓN</h3>
                <p>{recommendation}</p>
            </div>
            """, unsafe_allow_html=True)
        else:
            st.markdown(f"""
            <div class="risk-low">
                <h3>✅ RECOMENDACIÓN</h3>
                <p>{recommendation}</p>
            </div>
            """, unsafe_allow_html=True)
        
        # Guardar en historial
        st.session_state.analysis_history.append({
            'timestamp': datetime.now(),
            'classification': classification,
            'confidence': confidence,
            'risk_level': risk_level
        })
        
    except Exception as e:
        st.markdown(f"""
        <div class="error-container">
            <h3>❌ Error mostrando resultado</h3>
            <p>{str(e)}</p>
        </div>
        """, unsafe_allow_html=True)
        
        if st.checkbox("🐛 Ver detalles del error"):
            st.code(traceback.format_exc())

def call_analysis_api(endpoint: str, data: Optional[Dict] = None, files: Optional[Dict] = None) -> Dict[str, Any]:
    """Llama a la API con manejo robusto de errores."""
    try:
        base_url = st.session_state.api_config['base_url']
        timeout = st.session_state.api_config['timeout']
        
        if files:
            response = requests.post(f"{base_url}/{endpoint}", files=files, timeout=timeout)
        else:
            response = requests.post(f"{base_url}/{endpoint}", json=data, timeout=timeout)
        
        if response.status_code == 200:
            return {'success': True, 'data': response.json()}
        elif response.status_code == 422:
            return {
                'success': False,
                'error': f"Datos inválidos: {response.json().get('detail', 'Error de validación')}",
                'code': 422
            }
        elif response.status_code == 500:
            return {
                'success': False,
                'error': "Error interno del servidor. Verifica la configuración de OPENAI_API_KEY.",
                'code': 500
            }
        else:
            return {
                'success': False,
                'error': f"Error HTTP {response.status_code}",
                'code': response.status_code
            }
            
    except requests.exceptions.ConnectionError:
        return {
            'success': False,
            'error': f"❌ No se puede conectar con la API en {st.session_state.api_config['base_url']}",
            'code': 'CONNECTION_ERROR'
        }
    except requests.exceptions.Timeout:
        return {
            'success': False,
            'error': f"⏱️ Timeout después de {timeout} segundos",
            'code': 'TIMEOUT'
        }
    except Exception as e:
        return {
            'success': False,
            'error': f"Error inesperado: {str(e)}",
            'code': 'UNKNOWN_ERROR'
        }

def sidebar():
    """Sidebar con configuración."""
    st.sidebar.markdown("## ⚙️ Configuración")
    
    # Estado de conexión
    api_status = check_api_connection()
    if api_status['status'] == 'connected':
        st.sidebar.markdown(
            '<div class="status-connected">🟢 API Conectada</div>', 
            unsafe_allow_html=True
        )
    else:
        st.sidebar.markdown(
            '<div class="status-disconnected">🔴 API Desconectada</div>', 
            unsafe_allow_html=True
        )
        st.sidebar.error(api_status['message'])
    
    # Configuración de API
    with st.sidebar.expander("🔧 Configuración API"):
        new_base_url = st.text_input(
            "URL Base:",
            value=st.session_state.api_config['base_url']
        )
        new_timeout = st.slider(
            "Timeout (seg):",
            min_value=10,
            max_value=180,
            value=st.session_state.api_config['timeout']
        )
        
        if st.button("💾 Guardar"):
            st.session_state.api_config.update({
                'base_url': new_base_url,
                'timeout': new_timeout
            })
            st.success("✅ Guardado")
            st.rerun()
    
    # Historial
    if st.session_state.analysis_history:
        st.sidebar.markdown("## 📈 Historial")
        
        total = len(st.session_state.analysis_history)
        phishing = sum(1 for a in st.session_state.analysis_history 
                      if a['classification'].upper() == 'PHISHING')
        
        st.sidebar.metric("Total", total)
        st.sidebar.metric("Phishing", phishing)
        
        if st.sidebar.button("🗑️ Limpiar"):
            st.session_state.analysis_history = []
            st.rerun()

def main():
    """Función principal."""
    sidebar()
    
    # Header
    st.markdown("""
    # 🛡️ Detector de Phishing Avanzado
    
    **Análisis multimodal con IA** - Detecta phishing en texto e imágenes
    """)
    
    # Verificar API
    api_status = check_api_connection()
    if api_status['status'] != 'connected':
        st.markdown(f"""
        <div class="error-container">
            <h3>❌ API No Disponible</h3>
            <p>{api_status['message']}</p>
            <p><strong>Soluciones:</strong></p>
            <ul>
                <li>Ejecuta: <code>python -m uvicorn app.api:app --host 0.0.0.0 --port 8000</code></li>
                <li>O ejecuta: <code>python run.py</code></li>
                <li>Verifica la URL en el sidebar</li>
            </ul>
        </div>
        """, unsafe_allow_html=True)
        return
    
    # Selector de entrada
    st.markdown("## 📥 Selecciona el Método")
    
    col1, col2, col3 = st.columns(3)
    
    with col1:
        if st.button("✍️ Texto Directo", use_container_width=True):
            st.session_state.input_method = "text"
    with col2:
        if st.button("📁 Subir Archivo", use_container_width=True):
            st.session_state.input_method = "file"
    with col3:
        if st.button("📋 Usar Ejemplo", use_container_width=True):
            st.session_state.input_method = "example"
    
    if 'input_method' not in st.session_state:
        st.session_state.input_method = "text"
    
    st.markdown("---")
    
    # Procesar según método
    if st.session_state.input_method == "text":
        handle_text_input()
    elif st.session_state.input_method == "file":
        handle_file_input()
    else:
        handle_example_input()

def handle_text_input():
    """Entrada de texto."""
    st.markdown("### ✍️ Entrada de Texto")
    
    email_text = st.text_area(
        "Contenido del email:",
        height=300,
        placeholder="""Pega aquí el contenido del email:

From: banco@seguridad-bbva.com
Subject: Urgente: Verifica tu cuenta
To: usuario@email.com

Estimado cliente,
Su cuenta será suspendida...
""",
        key="email_text_input"
    )
    
    # Imágenes
    st.markdown("#### 🖼️ Imágenes (opcional)")
    uploaded_images = st.file_uploader(
        "Selecciona imágenes:",
        accept_multiple_files=True,
        type=["png", "jpg", "jpeg", "gif"],
        help="Múltiples imágenes se analizan junto al texto"
    )
    
    # Preview imágenes
    if uploaded_images:
        st.markdown("**Preview:**")
        cols = st.columns(min(len(uploaded_images), 4))
        for i, img in enumerate(uploaded_images):
            with cols[i % 4]:
                try:
                    image = Image.open(img)
                    st.image(image, caption=img.name, use_column_width=True)
                except Exception as e:
                    st.error(f"Error: {str(e)}")
    
    # Botones
    col1, col2 = st.columns([2, 1])
    
    with col1:
        analyze_btn = st.button(
            "🔍 Analizar Email Completo",
            type="primary",
            use_container_width=True,
            disabled=not email_text.strip()
        )
    
    with col2:
        quick_btn = st.button(
            "⚡ Análisis Rápido",
            use_container_width=True,
            disabled=not email_text.strip(),
            help="Análisis básico más rápido"
        )
    
    # Procesar
    if analyze_btn or quick_btn:
        if not email_text.strip():
            st.warning("⚠️ Introduce el contenido del email")
            return
        
        perform_analysis(email_text, uploaded_images, enhanced=analyze_btn)

def handle_file_input():
    """Entrada por archivo."""
    st.markdown("### 📁 Subir Archivo")
    
    uploaded_file = st.file_uploader(
        "Selecciona archivo:",
        type=["txt", "eml", "msg"],
        help="Formatos: .txt, .eml, .msg"
    )
    
    if uploaded_file:
        # Info del archivo
        col1, col2, col3 = st.columns(3)
        with col1:
            st.metric("Nombre", uploaded_file.name)
        with col2:
            st.metric("Tamaño", f"{uploaded_file.size} bytes")
        with col3:
            st.metric("Tipo", uploaded_file.type or "text/plain")
        
        # Preview
        try:
            preview = uploaded_file.read().decode('utf-8')[:500]
            uploaded_file.seek(0)
            
            with st.expander("👁️ Preview"):
                st.text(preview + ("..." if len(preview) == 500 else ""))
        except Exception as e:
            st.warning(f"⚠️ No se puede mostrar preview: {str(e)}")
        
        # Botones
        col1, col2 = st.columns(2)
        
        with col1:
            if st.button("🔍 Análisis Completo", type="primary", use_container_width=True):
                perform_file_analysis(uploaded_file, enhanced=True)
        
        with col2:
            if st.button("⚡ Análisis Rápido", use_container_width=True):
                perform_file_analysis(uploaded_file, enhanced=False)

def handle_example_input():
    """Ejemplos predefinidos."""
    st.markdown("### 📋 Ejemplos")
    
    examples = {
        "🚨 Phishing Bancario": "data/example_phishing_email.txt",
        "✅ Email Legítimo": "data/example_legit_email.txt"
    }
    
    selected = st.selectbox("Selecciona ejemplo:", list(examples.keys()))
    if selected:
        example_file = examples[selected]
    else:
        return
    
    # Cargar ejemplo
    try:
        if os.path.exists(example_file):
            with open(example_file, 'r', encoding='utf-8') as f:
                content = f.read()
            
            st.text_area(
                "Contenido:",
                value=content,
                height=300,
                key=f"example_{selected}"
            )
            
            # Botones
            col1, col2 = st.columns(2)
            
            with col1:
                if st.button("🔍 Análisis Completo", type="primary", use_container_width=True):
                    perform_analysis(content, [], enhanced=True)
            
            with col2:
                if st.button("⚡ Análisis Rápido", use_container_width=True):
                    perform_analysis(content, [], enhanced=False)
        else:
            st.error(f"❌ Archivo no encontrado: {example_file}")
    except Exception as e:
        st.error(f"❌ Error: {str(e)}")

def perform_analysis(email_text: str, uploaded_images, enhanced: bool = True):
    """Realiza análisis con estado de carga."""
    
    # Contenedores
    status_container = st.container()
    result_container = st.container()
    
    with status_container:
        st.markdown("## 🔄 Analizando...")
        progress = st.progress(0)
        status = st.empty()
        
        try:
            # Preparar
            status.text("📝 Preparando datos...")
            progress.progress(20)
            time.sleep(0.5)
            
            # Procesar imágenes
            images = []
            if uploaded_images:
                for img in uploaded_images:
                    try:
                        base64_img = image_to_base64(img)
                        if base64_img:
                            images.append(f"data:image/jpeg;base64,{base64_img}")
                    except Exception as e:
                        st.warning(f"⚠️ Error con {img.name}: {str(e)}")
            
            # Enviar a API
            status.text("📡 Enviando a API...")
            progress.progress(50)
            
            data = {"text": email_text, "images": images}
            endpoint = "analyze/"
            
            api_result = call_analysis_api(endpoint, data)
            progress.progress(90)
            
            if not api_result['success']:
                progress.progress(100)
                status.text("❌ Error")
                
                st.markdown(f"""
                <div class="error-container">
                    <h3>❌ Error en el Análisis</h3>
                    <p>{api_result['error']}</p>
                </div>
                """, unsafe_allow_html=True)
                
                # Sugerencias
                if api_result.get('code') == 'CONNECTION_ERROR':
                    st.info("💡 Ejecuta la API: `python -m uvicorn app.api:app --host 0.0.0.0 --port 8000`")
                elif api_result.get('code') == 'TIMEOUT':
                    st.info("💡 Aumenta el timeout en configuración o prueba análisis rápido")
                elif api_result.get('code') == 500:
                    st.info("💡 Verifica que OPENAI_API_KEY esté configurada correctamente")
                
                return
            
            # Éxito
            status.text("✅ Completado")
            progress.progress(100)
            time.sleep(0.5)
            
            # Limpiar estado de carga
            status_container.empty()
            
            # Mostrar resultado
            with result_container:
                display_enhanced_analysis_result(api_result['data'])
            
        except Exception as e:
            progress.progress(100)
            status.text("❌ Error inesperado")
            
            st.markdown(f"""
            <div class="error-container">
                <h3>❌ Error Inesperado</h3>
                <p>{str(e)}</p>
            </div>
            """, unsafe_allow_html=True)
            
            if st.checkbox("🐛 Ver traceback completo"):
                st.code(traceback.format_exc())

def perform_file_analysis(uploaded_file, enhanced: bool = True):
    """Análisis de archivo."""
    status_container = st.container()
    result_container = st.container()
    
    with status_container:
        st.markdown("## 🔄 Analizando Archivo...")
        progress = st.progress(0)
        status = st.empty()
        
        try:
            status.text("📁 Procesando archivo...")
            progress.progress(30)
            
            uploaded_file.seek(0)
            files = {"file": uploaded_file}
            
            status.text("📡 Enviando...")
            progress.progress(60)
            
            api_result = call_analysis_api("analyze/file/", files=files)
            progress.progress(90)
            
            if not api_result['success']:
                progress.progress(100)
                status.text("❌ Error")
                st.error(f"Error: {api_result['error']}")
                return
            
            status.text("✅ Completado")
            progress.progress(100)
            time.sleep(0.5)
            
            status_container.empty()
            
            with result_container:
                display_enhanced_analysis_result(api_result['data'])
                
        except Exception as e:
            progress.progress(100)
            status.text("❌ Error")
            st.error(f"Error: {str(e)}")

if __name__ == "__main__":
    main() 