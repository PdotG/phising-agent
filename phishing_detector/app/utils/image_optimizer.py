"""Utilidades para optimización y gestión de imágenes."""

import io
import base64
from typing import Tuple, Optional, Dict
from PIL import Image
import logging

logger = logging.getLogger(__name__)

class ImageOptimizer:
    """Optimizador de imágenes para análisis multimodal."""
    
    def __init__(self, config: Optional[Dict] = None):
        self.config = config or {}
        self.max_size = self.config.get('max_image_size', (1024, 1024))
        self.quality = self.config.get('jpeg_quality', 85)
        self.format = self.config.get('output_format', 'JPEG')
    
    def optimize_image(self, image_data: bytes) -> Tuple[bytes, Dict]:
        """Optimiza una imagen para el análisis.
        
        Returns:
            Tuple[bytes, Dict]: Imagen optimizada y metadatos
        """
        try:
            # Abrir imagen desde bytes
            img = Image.open(io.BytesIO(image_data))
            
            # Convertir a RGB si es necesario
            if img.mode in ('RGBA', 'P'):
                img = img.convert('RGB')
            
            # Redimensionar si es muy grande
            if img.size[0] > self.max_size[0] or img.size[1] > self.max_size[1]:
                img.thumbnail(self.max_size, Image.Resampling.LANCZOS)
            
            # Guardar imagen optimizada
            output = io.BytesIO()
            img.save(output, format=self.format, quality=self.quality, optimize=True)
            optimized_data = output.getvalue()
            
            metadata = {
                'original_size': len(image_data),
                'optimized_size': len(optimized_data),
                'reduction': f"{(1 - len(optimized_data)/len(image_data))*100:.1f}%",
                'format': self.format,
                'dimensions': img.size
            }
            
            return optimized_data, metadata
            
        except Exception as e:
            logger.error(f"Error optimizando imagen: {e}")
            return image_data, {'error': str(e)}
    
    def base64_to_bytes(self, base64_str: str) -> bytes:
        """Convierte base64 a bytes."""
        try:
            # Eliminar el prefijo de data URL si existe
            if ',' in base64_str:
                base64_str = base64_str.split(',')[1]
            return base64.b64decode(base64_str)
        except Exception as e:
            logger.error(f"Error decodificando base64: {e}")
            raise
    
    def bytes_to_base64(self, image_data: bytes, include_prefix: bool = True) -> str:
        """Convierte bytes a base64."""
        b64 = base64.b64encode(image_data).decode()
        if include_prefix:
            return f"data:image/{self.format.lower()};base64,{b64}"
        return b64
    
    def optimize_base64(self, base64_str: str) -> Tuple[str, Dict]:
        """Optimiza una imagen en formato base64."""
        try:
            # Convertir base64 a bytes
            image_data = self.base64_to_bytes(base64_str)
            
            # Optimizar
            optimized_data, metadata = self.optimize_image(image_data)
            
            # Convertir de vuelta a base64
            optimized_b64 = self.bytes_to_base64(optimized_data)
            
            return optimized_b64, metadata
            
        except Exception as e:
            logger.error(f"Error en optimize_base64: {e}")
            return base64_str, {'error': str(e)} 