"""Soporte multiidioma para detección de phishing."""

from typing import Dict, List, Optional
from dataclasses import dataclass
import json
import logging

logger = logging.getLogger(__name__)

@dataclass
class LanguagePatterns:
    """Patrones de phishing por idioma."""
    urgency_words: List[str]
    action_words: List[str]
    sensitive_words: List[str]
    common_subjects: List[str]
    greetings: List[str]

class LanguageManager:
    """Gestor de patrones multiidioma para phishing."""
    
    # Patrones predefinidos por idioma
    DEFAULT_PATTERNS = {
        "es": LanguagePatterns(
            urgency_words=["urgente", "inmediato", "importante", "atención", "suspender", "bloquear"],
            action_words=["verificar", "confirmar", "actualizar", "validar", "clic", "acceder"],
            sensitive_words=["contraseña", "pin", "tarjeta", "cuenta", "dni", "seguridad"],
            common_subjects=["Verificación necesaria", "Problema con su cuenta", "Actualización requerida"],
            greetings=["Estimado cliente", "Apreciado usuario", "Distinguido cliente"]
        ),
        "en": LanguagePatterns(
            urgency_words=["urgent", "immediate", "important", "attention", "suspend", "block"],
            action_words=["verify", "confirm", "update", "validate", "click", "access"],
            sensitive_words=["password", "pin", "card", "account", "ssn", "security"],
            common_subjects=["Verification needed", "Account issue", "Update required"],
            greetings=["Dear customer", "Dear user", "Valued client"]
        ),
        "fr": LanguagePatterns(
            urgency_words=["urgent", "immédiat", "important", "attention", "suspendre", "bloquer"],
            action_words=["vérifier", "confirmer", "mettre à jour", "valider", "cliquer", "accéder"],
            sensitive_words=["mot de passe", "pin", "carte", "compte", "identité", "sécurité"],
            common_subjects=["Vérification nécessaire", "Problème de compte", "Mise à jour requise"],
            greetings=["Cher client", "Cher utilisateur", "Client estimé"]
        )
    }
    
    def __init__(self, custom_patterns: Optional[Dict] = None):
        """Inicializa el gestor con patrones personalizados opcionales."""
        self.patterns = self.DEFAULT_PATTERNS.copy()
        if custom_patterns:
            self._merge_custom_patterns(custom_patterns)
    
    def _merge_custom_patterns(self, custom_patterns: Dict):
        """Combina patrones personalizados con los predefinidos."""
        for lang, patterns in custom_patterns.items():
            if lang in self.patterns:
                # Actualizar patrones existentes
                current = self.patterns[lang]
                for key, value in patterns.items():
                    if hasattr(current, key):
                        current_list = getattr(current, key)
                        current_list.extend([v for v in value if v not in current_list])
            else:
                # Añadir nuevo idioma
                self.patterns[lang] = LanguagePatterns(**patterns)
    
    def detect_language(self, text: str) -> str:
        """Detecta el idioma del texto basado en patrones.
        
        Método simple basado en coincidencias de patrones.
        Para producción, usar una librería como langdetect.
        """
        max_matches = 0
        detected_lang = "en"  # default
        
        for lang, patterns in self.patterns.items():
            matches = 0
            all_words = []
            for pattern_list in [patterns.urgency_words, patterns.action_words, 
                               patterns.greetings, patterns.common_subjects]:
                all_words.extend(pattern_list)
            
            for word in all_words:
                if word.lower() in text.lower():
                    matches += 1
            
            if matches > max_matches:
                max_matches = matches
                detected_lang = lang
        
        return detected_lang
    
    def get_patterns(self, language: str) -> LanguagePatterns:
        """Obtiene los patrones para un idioma específico."""
        return self.patterns.get(language, self.patterns["en"])
    
    def analyze_text(self, text: str, language: Optional[str] = None) -> Dict:
        """Analiza texto buscando patrones de phishing en el idioma correcto."""
        if not language:
            language = self.detect_language(text)
        
        patterns = self.get_patterns(language)
        text_lower = text.lower()
        
        analysis = {
            "language": language,
            "urgency_detected": False,
            "action_required": False,
            "sensitive_info_requested": False,
            "matches": {
                "urgency": [],
                "action": [],
                "sensitive": [],
                "subject_match": None,
                "greeting_match": None
            }
        }
        
        # Buscar coincidencias
        for word in patterns.urgency_words:
            if word.lower() in text_lower:
                analysis["urgency_detected"] = True
                analysis["matches"]["urgency"].append(word)
        
        for word in patterns.action_words:
            if word.lower() in text_lower:
                analysis["action_required"] = True
                analysis["matches"]["action"].append(word)
        
        for word in patterns.sensitive_words:
            if word.lower() in text_lower:
                analysis["sensitive_info_requested"] = True
                analysis["matches"]["sensitive"].append(word)
        
        # Buscar asuntos comunes
        for subject in patterns.common_subjects:
            if subject.lower() in text_lower:
                analysis["matches"]["subject_match"] = subject
                break
        
        # Buscar saludos típicos
        for greeting in patterns.greetings:
            if greeting.lower() in text_lower:
                analysis["matches"]["greeting_match"] = greeting
                break
        
        return analysis 