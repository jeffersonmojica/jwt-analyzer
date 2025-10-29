import base64
import json
import hmac
import hashlib
from datetime import datetime

class JWTAnalyzer:
    """Analizador completo de JWT - Todas las fases"""
    
    def __init__(self):
        self.errors = []
        self.warnings = []
        self.tokens = []
        self.symbol_table = {}
    
    # ============== FASE 1: ANÁLISIS LÉXICO ==============
    def lexical_analysis(self, jwt_string):
        """
        Fase 1: Análisis Léxico
        Identifica los tokens del JWT
        """
        self.tokens = []
        parts = jwt_string.split('.')
        
        if len(parts) != 3:
            raise ValueError(f"Token malformado: se esperaban 3 partes, se encontraron {len(parts)}")
        
        position = 0
        self.tokens.append({
            'type': 'HEADER',
            'value': parts[0],
            'position': position,
            'length': len(parts[0])
        })
        
        position += len(parts[0])
        self.tokens.append({
            'type': 'SEPARATOR',
            'value': '.',
            'position': position,
            'length': 1
        })
        
        position += 1
        self.tokens.append({
            'type': 'PAYLOAD',
            'value': parts[1],
            'position': position,
            'length': len(parts[1])
        })
        
        position += len(parts[1])
        self.tokens.append({
            'type': 'SEPARATOR',
            'value': '.',
            'position': position,
            'length': 1
        })
        
        position += 1
        self.tokens.append({
            'type': 'SIGNATURE',
            'value': parts[2],
            'position': position,
            'length': len(parts[2])
        })
        
        return {
            'tokens': self.tokens,
            'parts': parts,
            'total_tokens': len(self.tokens)
        }
    
    # ============== FASE 4: DECODIFICACIÓN ==============
    @staticmethod
    def base64url_decode(data):
        """
        Decodificador Base64URL
        """
        # Agregar padding si es necesario
        padding = 4 - (len(data) % 4)
        if padding != 4:
            data += '=' * padding
        
        # Reemplazar caracteres URL-safe
        data = data.replace('-', '+').replace('_', '/')
        
        try:
            decoded = base64.b64decode(data)
            return json.loads(decoded.decode('utf-8'))
        except Exception as e:
            raise ValueError(f"Error decodificando Base64URL: {str(e)}")
    
    def decode_jwt(self, jwt_string):
        """
        Fase 4: Decodificación completa
        """
        lexical_result = self.lexical_analysis(jwt_string)
        parts = lexical_result['parts']
        
        try:
            header = self.base64url_decode(parts[0])
            payload = self.base64url_decode(parts[1])
            signature = parts[2]
            
            return {
                'header': header,
                'payload': payload,
                'signature': signature,
                'raw_parts': parts
            }
        except Exception as e:
            raise ValueError(f"Error en decodificación: {str(e)}")
    
    # ============== FASE 2: ANÁLISIS SINTÁCTICO ==============
    def syntactic_analysis(self, header, payload):
        """
        Fase 2: Análisis Sintáctico
        Valida la estructura JSON y tipos básicos
        """
        syntax_errors = []
        
        # Validar que header sea un objeto
        if not isinstance(header, dict):
            syntax_errors.append("Header debe ser un objeto JSON")
        
        # Validar que payload sea un objeto
        if not isinstance(payload, dict):
            syntax_errors.append("Payload debe ser un objeto JSON")
        
        # Validar que no estén vacíos
        if isinstance(header, dict) and len(header) == 0:
            syntax_errors.append("Header no puede estar vacío")
        
        if isinstance(payload, dict) and len(payload) == 0:
            syntax_errors.append("Payload no puede estar vacío")
        
        return {
            'valid': len(syntax_errors) == 0,
            'errors': syntax_errors
        }
    
    # ============== FASE 3: ANÁLISIS SEMÁNTICO ==============
    def semantic_analysis(self, header, payload):
        """
        Fase 3: Análisis Semántico
        Valida campos obligatorios, tipos de datos, y claims estándar
        """
        semantic_errors = []
        semantic_warnings = []
        self.symbol_table = {}
        
        # ========== VALIDACIÓN DEL HEADER ==========
        
        # Campo obligatorio: alg
        if 'alg' not in header:
            semantic_errors.append("Campo obligatorio 'alg' faltante en header")
        else:
            self.symbol_table['header.alg'] = {
                'type': type(header['alg']).__name__,
                'value': header['alg'],
                'required': True
            }
            
            # Validar algoritmos estándar
            valid_algorithms = ['HS256', 'HS384', 'HS512', 'RS256', 'RS384', 'RS512', 'ES256', 'ES384', 'ES512', 'none']
            if header['alg'] not in valid_algorithms:
                semantic_warnings.append(f"Algoritmo '{header['alg']}' no es estándar")
            
            # Advertencia sobre 'none'
            if header['alg'] == 'none':
                semantic_warnings.append("Algoritmo 'none' no es seguro para producción")
        
        # Campo recomendado: typ
        if 'typ' not in header:
            semantic_warnings.append("Campo recomendado 'typ' faltante en header")
        else:
            self.symbol_table['header.typ'] = {
                'type': type(header['typ']).__name__,
                'value': header['typ'],
                'required': False
            }
            
            if header['typ'] != 'JWT':
                semantic_warnings.append(f"Tipo '{header['typ']}' no es estándar (se esperaba 'JWT')")
        
        # ========== VALIDACIÓN DEL PAYLOAD ==========
        
        standard_claims = {
            'iss': 'string',  # Issuer
            'sub': 'string',  # Subject
            'aud': 'string',  # Audience
            'exp': 'number',  # Expiration Time
            'nbf': 'number',  # Not Before
            'iat': 'number',  # Issued At
            'jti': 'string'   # JWT ID
        }
        
        current_timestamp = int(datetime.now().timestamp())
        
        # Validar claims estándar
        for claim, expected_type in standard_claims.items():
            if claim in payload:
                value = payload[claim]
                actual_type = 'number' if isinstance(value, (int, float)) else 'string' if isinstance(value, str) else type(value).__name__
                
                self.symbol_table[f'payload.{claim}'] = {
                    'type': actual_type,
                    'value': value,
                    'standard': True,
                    'expected_type': expected_type
                }
                
                # Validar tipo de dato
                if expected_type == 'number' and not isinstance(value, (int, float)):
                    semantic_errors.append(f"Claim '{claim}' debe ser numérico, se encontró {actual_type}")
                elif expected_type == 'string' and not isinstance(value, str):
                    semantic_errors.append(f"Claim '{claim}' debe ser string, se encontró {actual_type}")
        
        # ========== VALIDACIÓN TEMPORAL ==========
        
        # Validar expiración (exp)
        if 'exp' in payload:
            if isinstance(payload['exp'], (int, float)):
                if payload['exp'] < current_timestamp:
                    exp_date = datetime.fromtimestamp(payload['exp']).strftime('%Y-%m-%d %H:%M:%S')
                    semantic_errors.append(f"Token expirado. Expiró el {exp_date}")
                else:
                    exp_date = datetime.fromtimestamp(payload['exp']).strftime('%Y-%m-%d %H:%M:%S')
                    semantic_warnings.append(f"Token válido hasta {exp_date}")
        else:
            semantic_warnings.append("Claim 'exp' no presente. Token sin fecha de expiración")
        
        # Validar not before (nbf)
        if 'nbf' in payload:
            if isinstance(payload['nbf'], (int, float)):
                if payload['nbf'] > current_timestamp:
                    nbf_date = datetime.fromtimestamp(payload['nbf']).strftime('%Y-%m-%d %H:%M:%S')
                    semantic_errors.append(f"Token aún no válido. Será válido desde {nbf_date}")
        
        # Validar issued at (iat)
        if 'iat' in payload:
            if isinstance(payload['iat'], (int, float)):
                iat_date = datetime.fromtimestamp(payload['iat']).strftime('%Y-%m-%d %H:%M:%S')
                self.symbol_table['payload.iat']['human_readable'] = iat_date
        
        # Agregar claims personalizados a la tabla de símbolos
        for key, value in payload.items():
            if key not in standard_claims:
                self.symbol_table[f'payload.{key}'] = {
                    'type': type(value).__name__,
                    'value': value,
                    'standard': False,
                    'custom': True
                }
        
        return {
            'valid': len(semantic_errors) == 0,
            'errors': semantic_errors,
            'warnings': semantic_warnings,
            'symbol_table': self.symbol_table
        }
    
    # ============== FASE 6: VERIFICACIÓN CRIPTOGRÁFICA ==============
    @staticmethod
    def base64url_encode(data):
        """Codificador Base64URL"""
        if isinstance(data, str):
            data = data.encode('utf-8')
        encoded = base64.urlsafe_b64encode(data).decode('utf-8')
        return encoded.rstrip('=')
    
    def verify_signature(self, jwt_string, secret_key, header, payload):
        """
        Fase 6: Verificación Criptográfica
        Valida la firma del JWT
        """
        algorithm = header.get('alg', 'none')
        parts = jwt_string.split('.')
        
        if len(parts) != 3:
            return {
                'valid': False,
                'error': 'Token malformado',
                'algorithm': algorithm
            }
        
        message = f"{parts[0]}.{parts[1]}"
        signature = parts[2]
        
        # Algoritmo 'none'
        if algorithm == 'none':
            return {
                'valid': signature == '',
                'algorithm': 'none',
                'message': 'Token sin firma (algoritmo none)'
            }
        
        # Algoritmos HMAC
        hash_algorithms = {
            'HS256': hashlib.sha256,
            'HS384': hashlib.sha384,
            'HS512': hashlib.sha512
        }
        
        if algorithm not in hash_algorithms:
            return {
                'valid': False,
                'error': f"Algoritmo '{algorithm}' no soportado en esta implementación",
                'algorithm': algorithm
            }
        
        try:
            # Generar firma esperada
            hash_func = hash_algorithms[algorithm]
            expected_signature = hmac.new(
                secret_key.encode('utf-8'),
                message.encode('utf-8'),
                hash_func
            ).digest()
            
            expected_signature_b64 = self.base64url_encode(expected_signature)
            
            # Comparar firmas
            is_valid = hmac.compare_digest(expected_signature_b64, signature)
            
            return {
                'valid': is_valid,
                'algorithm': algorithm,
                'expected_signature': expected_signature_b64,
                'received_signature': signature,
                'message': 'Firma válida' if is_valid else 'Firma inválida'
            }
        
        except Exception as e:
            return {
                'valid': False,
                'error': str(e),
                'algorithm': algorithm
            }
    
    # ============== FASE 5: CODIFICACIÓN ==============
    def encode_jwt(self, header, payload, secret_key):
        """
        Fase 5: Codificación de JWT
        Genera un nuevo token JWT
        """
        # Validar header
        if 'alg' not in header:
            raise ValueError("Header debe contener el campo 'alg'")
        
        if 'typ' not in header:
            header['typ'] = 'JWT'
        
        # Codificar header y payload
        header_json = json.dumps(header, separators=(',', ':')).encode('utf-8')
        payload_json = json.dumps(payload, separators=(',', ':')).encode('utf-8')
        
        header_b64 = self.base64url_encode(header_json)
        payload_b64 = self.base64url_encode(payload_json)
        
        message = f"{header_b64}.{payload_b64}"
        
        # Generar firma
        algorithm = header['alg']
        
        if algorithm == 'none':
            signature = ''
        elif algorithm in ['HS256', 'HS384', 'HS512']:
            hash_algorithms = {
                'HS256': hashlib.sha256,
                'HS384': hashlib.sha384,
                'HS512': hashlib.sha512
            }
            
            hash_func = hash_algorithms[algorithm]
            signature_bytes = hmac.new(
                secret_key.encode('utf-8'),
                message.encode('utf-8'),
                hash_func
            ).digest()
            
            signature = self.base64url_encode(signature_bytes)
        else:
            raise ValueError(f"Algoritmo '{algorithm}' no soportado")
        
        jwt_token = f"{message}.{signature}"
        
        return {
            'token': jwt_token,
            'header': header,
            'payload': payload,
            'algorithm': algorithm
        }
    
    # ============== ANÁLISIS COMPLETO ==============
    def analyze_complete(self, jwt_string, secret_key):
        """
        Ejecuta todas las fases del análisis
        """
        try:
            # Fase 1: Léxico
            lexical_result = self.lexical_analysis(jwt_string)
            
            # Fase 4: Decodificación
            decoded = self.decode_jwt(jwt_string)
            
            # Fase 2: Sintáctico
            syntactic_result = self.syntactic_analysis(decoded['header'], decoded['payload'])
            
            # Fase 3: Semántico
            semantic_result = self.semantic_analysis(decoded['header'], decoded['payload'])
            
            # Fase 6: Verificación
            signature_result = self.verify_signature(jwt_string, secret_key, decoded['header'], decoded['payload'])
            
            # Determinar validez general
            is_valid = (
                syntactic_result['valid'] and
                semantic_result['valid'] and
                signature_result['valid']
            )
            
            return {
                'success': True,
                'is_valid': is_valid,
                'phases': {
                    'phase1_lexical': lexical_result,
                    'phase2_syntactic': syntactic_result,
                    'phase3_semantic': semantic_result,
                    'phase4_decoded': decoded,
                    'phase6_signature': signature_result
                },
                'summary': {
                    'total_errors': len(syntactic_result['errors']) + len(semantic_result['errors']),
                    'total_warnings': len(semantic_result['warnings']),
                    'signature_valid': signature_result['valid']
                }
            }
        
        except Exception as e:
            return {
                'success': False,
                'error': str(e),
                'is_valid': False
            }