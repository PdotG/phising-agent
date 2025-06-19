"""Analizador de attachments para detectar archivos maliciosos."""

import hashlib
import logging
import os
import tempfile
from typing import Dict, List, Optional, Any, Tuple
from pathlib import Path
import email
from email.mime.multipart import MIMEMultipart
from email.mime.base import MIMEBase
import base64
import zipfile
import re

logger = logging.getLogger(__name__)

class AttachmentAnalyzer:
    """Analizador de attachments para detección de malware y archivos sospechosos."""
    
    # Extensiones peligrosas
    DANGEROUS_EXTENSIONS = {
        'exe', 'bat', 'cmd', 'com', 'pif', 'scr', 'vbs', 'vbe', 'js', 'jar',
        'ps1', 'psm1', 'ws', 'wsf', 'wsc', 'wsh', 'msi', 'msp', 'reg',
        'application', 'gadget', 'msc', 'hta', 'cpl', 'dll', 'ocx', 'sys',
        'drv', 'tmp', 'lnk', 'url', 'website', 'scf', 'inf', 'cab'
    }
    
    # MIME types peligrosos
    DANGEROUS_MIME_TYPES = {
        'application/x-executable',
        'application/x-msdownload',
        'application/x-msdos-program',
        'application/x-dosexec',
        'application/vnd.microsoft.portable-executable',
        'application/x-winexe',
        'application/javascript',
        'text/javascript',
        'application/x-javascript',
        'application/x-shellscript',
        'text/x-script',
        'application/java-archive',
        'application/x-java-archive'
    }
    
    # Extensiones que pueden contener macros
    MACRO_CAPABLE = {
        'doc', 'docx', 'docm', 'dot', 'dotm', 'xls', 'xlsx', 'xlsm', 'xlt',
        'xltm', 'xlam', 'ppt', 'pptx', 'pptm', 'pot', 'potm', 'ppam', 'ppsm'
    }
    
    def __init__(self, config: Optional[Dict] = None):
        self.config = config or {}
        self.max_file_size = self.config.get('max_file_size', 50 * 1024 * 1024)  # 50MB
        self.scan_archives = self.config.get('scan_archives', True)
        
        # Inicializar magic mime detector de forma segura
        try:
            import magic  # type: ignore
            self.magic_mime = magic.Magic(mime=True)
        except ImportError:
            logger.warning("python-magic no disponible, usando detección básica de MIME")
            self.magic_mime = None
        
    def analyze_email_attachments(self, email_content: str) -> Dict[str, Any]:
        """Analiza todos los attachments de un email."""
        try:
            # Parsear email
            msg = email.message_from_string(email_content)
            attachments = []
            
            # Buscar attachments
            for part in msg.walk():
                if part.get_content_disposition() == 'attachment':
                    attachment_data = self._extract_attachment(part)
                    if attachment_data:
                        analysis = self.analyze_attachment(
                            attachment_data['content'],
                            attachment_data['filename']
                        )
                        attachments.append({
                            **attachment_data,
                            'analysis': analysis
                        })
            
            return {
                'total_attachments': len(attachments),
                'attachments': attachments,
                'has_dangerous': any(att['analysis']['is_dangerous'] for att in attachments),
                'risk_score': self._calculate_overall_risk(attachments)
            }
            
        except Exception as e:
            logger.error(f"Error analizando attachments: {e}")
            return {
                'error': str(e),
                'total_attachments': 0,
                'attachments': [],
                'has_dangerous': False,
                'risk_score': 0.0
            }
    
    def _extract_attachment(self, part) -> Optional[Dict[str, Any]]:
        """Extrae datos de un attachment."""
        try:
            filename = part.get_filename()
            if not filename:
                return None
            
            content = part.get_payload(decode=True)
            if not content:
                return None
            
            return {
                'filename': filename,
                'content': content,
                'size': len(content),
                'content_type': part.get_content_type()
            }
        except Exception as e:
            logger.error(f"Error extrayendo attachment: {e}")
            return None
    
    def analyze_attachment(self, content: bytes, filename: str) -> Dict[str, Any]:
        """Analiza un attachment individual."""
        analysis = {
            'filename': filename,
            'size': len(content),
            'is_dangerous': False,
            'risk_score': 0.0,
            'threats': [],
            'file_type': 'unknown',
            'mime_type': 'unknown',
            'md5_hash': hashlib.md5(content).hexdigest(),
            'sha256_hash': hashlib.sha256(content).hexdigest()
        }
        
        try:
            # Analizar extensión primero
            extension = Path(filename).suffix.lower().lstrip('.')
            analysis['extension'] = extension
            
            # Detectar tipo MIME
            if self.magic_mime:
                analysis['mime_type'] = self.magic_mime.from_buffer(content)
            else:
                # Fallback básico basado en extensión
                mime_map = {
                    'pdf': 'application/pdf',
                    'exe': 'application/x-executable',
                    'zip': 'application/zip',
                    'txt': 'text/plain',
                    'jpg': 'image/jpeg',
                    'png': 'image/png'
                }
                analysis['mime_type'] = mime_map.get(extension, 'application/octet-stream')
            
            # Verificar si es peligroso por extensión
            if extension in self.DANGEROUS_EXTENSIONS:
                analysis['is_dangerous'] = True
                analysis['threats'].append(f"Extensión peligrosa: .{extension}")
                analysis['risk_score'] += 0.8
            
            # Verificar MIME type peligroso
            if analysis['mime_type'] in self.DANGEROUS_MIME_TYPES:
                analysis['is_dangerous'] = True
                analysis['threats'].append(f"Tipo MIME peligroso: {analysis['mime_type']}")
                analysis['risk_score'] += 0.7
            
            # Verificar capacidad de macros
            if extension in self.MACRO_CAPABLE:
                analysis['threats'].append("Archivo capaz de contener macros")
                analysis['risk_score'] += 0.3
            
            # Verificar tamaño sospechoso
            if len(content) > self.max_file_size:
                analysis['threats'].append(f"Archivo muy grande: {len(content)} bytes")
                analysis['risk_score'] += 0.2
            
            # Analizar contenido específico
            content_analysis = self._analyze_file_content(content, extension, analysis['mime_type'], filename)
            analysis.update(content_analysis)
            
            # Verificar archivos comprimidos
            if self.scan_archives and extension in ['zip', 'rar', '7z']:
                archive_analysis = self._analyze_archive(content, filename)
                analysis['archive_analysis'] = archive_analysis
                if archive_analysis.get('has_dangerous_files'):
                    analysis['is_dangerous'] = True
                    analysis['risk_score'] += 0.6
            
            # Normalizar risk_score
            analysis['risk_score'] = min(analysis['risk_score'], 1.0)
            
        except Exception as e:
            logger.error(f"Error analizando archivo {filename}: {e}")
            analysis['error'] = str(e)
        
        return analysis
    
    def _analyze_file_content(self, content: bytes, extension: str, mime_type: str, filename: str = "") -> Dict[str, Any]:
        """Analiza el contenido específico del archivo."""
        content_analysis = {}
        
        try:
            # Buscar patrones sospechosos en archivos de texto
            if mime_type.startswith('text/') or extension in ['txt', 'log', 'csv']:
                text_content = content.decode('utf-8', errors='ignore')
                suspicious_patterns = self._find_suspicious_patterns(text_content)
                if suspicious_patterns:
                    content_analysis['suspicious_text_patterns'] = suspicious_patterns
                    content_analysis['risk_score'] = content_analysis.get('risk_score', 0) + 0.4
            
            # Verificar firmas de archivos
            file_signature = content[:16].hex()
            signature_analysis = self._check_file_signature(file_signature, extension)
            content_analysis.update(signature_analysis)
            
            # Verificar doble extensión
            if filename and filename.count('.') > 1:
                content_analysis['double_extension'] = True
                content_analysis['threats'] = content_analysis.get('threats', [])
                content_analysis['threats'].append("Posible doble extensión")
                content_analysis['risk_score'] = content_analysis.get('risk_score', 0) + 0.3
            
        except Exception as e:
            logger.error(f"Error en análisis de contenido: {e}")
        
        return content_analysis
    
    def _find_suspicious_patterns(self, text: str) -> List[str]:
        """Busca patrones sospechosos en texto."""
        suspicious_patterns = []
        
        # Patrones comunes de malware/scripts
        patterns = [
            r'powershell\s+-[ewh]',  # PowerShell con flags sospechosos
            r'cmd\.exe\s+/c',        # Ejecución de comandos
            r'eval\s*\(',            # Evaluación de código
            r'base64\s*decode',      # Decodificación base64
            r'\\x[0-9a-f]{2}',       # Secuencias hexadecimales
            r'CreateObject\s*\(',    # Creación de objetos (VBScript)
            r'WScript\.Shell',       # Shell de Windows Script
            r'ActiveXObject',        # Objetos ActiveX
            r'document\.write',      # Escritura de documento (JavaScript)
            r'window\.location',     # Redirección (JavaScript)
        ]
        
        for pattern in patterns:
            if re.search(pattern, text, re.IGNORECASE):
                suspicious_patterns.append(pattern)
        
        return suspicious_patterns
    
    def _check_file_signature(self, signature: str, claimed_extension: str) -> Dict[str, Any]:
        """Verifica la firma del archivo contra la extensión reclamada."""
        # Firmas conocidas (primeros bytes en hex)
        known_signatures = {
            'pdf': ['255044462d'],  # %PDF-
            'zip': ['504b0304', '504b0506'],  # PK
            'exe': ['4d5a'],  # MZ
            'jpg': ['ffd8ff'],
            'png': ['89504e47'],
            'doc': ['d0cf11e0a1b11ae1'],  # Compound Document
            'docx': ['504b0304']  # ZIP (Office 2007+)
        }
        
        analysis = {}
        
        # Verificar si la firma coincide con la extensión
        if claimed_extension in known_signatures:
            expected_signatures = known_signatures[claimed_extension]
            signature_match = any(signature.startswith(sig.lower()) for sig in expected_signatures)
            
            if not signature_match:
                analysis['signature_mismatch'] = True
                analysis['threats'] = analysis.get('threats', [])
                analysis['threats'].append("Firma de archivo no coincide con extensión")
                analysis['risk_score'] = analysis.get('risk_score', 0) + 0.5
        
        return analysis
    
    def _analyze_archive(self, content: bytes, filename: str) -> Dict[str, Any]:
        """Analiza archivos comprimidos."""
        archive_analysis = {
            'is_archive': True,
            'files_inside': [],
            'has_dangerous_files': False,
            'total_files': 0
        }
        
        try:
            # Crear archivo temporal
            with tempfile.NamedTemporaryFile(delete=False, suffix='.zip') as temp_file:
                temp_file.write(content)
                temp_path = temp_file.name
            
            try:
                with zipfile.ZipFile(temp_path, 'r') as zip_ref:
                    file_list = zip_ref.namelist()
                    archive_analysis['total_files'] = len(file_list)
                    
                    for file_in_zip in file_list:
                        file_extension = Path(file_in_zip).suffix.lower().lstrip('.')
                        
                        file_info = {
                            'name': file_in_zip,
                            'extension': file_extension,
                            'is_dangerous': file_extension in self.DANGEROUS_EXTENSIONS
                        }
                        
                        if file_info['is_dangerous']:
                            archive_analysis['has_dangerous_files'] = True
                        
                        archive_analysis['files_inside'].append(file_info)
            
            finally:
                # Limpiar archivo temporal
                os.unlink(temp_path)
                
        except Exception as e:
            logger.error(f"Error analizando archivo: {e}")
            archive_analysis['error'] = str(e)
        
        return archive_analysis
    
    def _calculate_overall_risk(self, attachments: List[Dict]) -> float:
        """Calcula el riesgo general de todos los attachments."""
        if not attachments:
            return 0.0
        
        # Tomar el mayor riesgo individual
        max_risk = max(att['analysis'].get('risk_score', 0.0) for att in attachments)
        
        # Incrementar si hay múltiples attachments sospechosos
        dangerous_count = sum(1 for att in attachments if att['analysis'].get('is_dangerous', False))
        if dangerous_count > 1:
            max_risk = min(max_risk + (dangerous_count - 1) * 0.1, 1.0)
        
        return max_risk
    
    def get_attachment_summary(self, analysis: Dict[str, Any]) -> str:
        """Genera un resumen legible del análisis de attachments."""
        if analysis.get('error'):
            return f"❌ Error analizando attachments: {analysis['error']}"
        
        if analysis['total_attachments'] == 0:
            return "✅ No se encontraron attachments"
        
        summary = f"📎 {analysis['total_attachments']} attachment(s) encontrado(s)\n"
        
        if analysis['has_dangerous']:
            summary += "⚠️ ATTACHMENTS PELIGROSOS DETECTADOS:\n"
        else:
            summary += "✅ No se detectaron attachments peligrosos\n"
        
        for att in analysis['attachments']:
            att_analysis = att['analysis']
            status = "🔴 PELIGROSO" if att_analysis['is_dangerous'] else "✅ Seguro"
            summary += f"  • {att['filename']} ({att['size']} bytes) - {status}\n"
            
            if att_analysis.get('threats'):
                for threat in att_analysis['threats']:
                    summary += f"    - {threat}\n"
        
        summary += f"\n🎯 Riesgo general: {analysis['risk_score']*100:.1f}%"
        
        return summary 