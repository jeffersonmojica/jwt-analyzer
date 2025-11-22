import unittest
import sys
import os

# Agregar la ruta del backend al path
sys.path.insert(0, os.path.dirname(__file__))

from jwt_analyzer import JWTAnalyzer


class TestJWTAnalyzer(unittest.TestCase):
    """Suite de pruebas para el Analizador JWT"""
    
    def setUp(self):
        """Configuración antes de cada prueba"""
        self.analyzer = JWTAnalyzer()
        self.valid_token_hs256 = 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyLCJleHAiOjk5OTk5OTk5OTl9.Vg30C57s3l90JNap_VgMhKZjfc-p7SoBXaSAy8c28HA'
        self.secret_key = 'your-256-bit-secret'
    
    # ========== PRUEBAS FASE 1: ANÁLISIS LÉXICO ==========
    
    def test_lexical_analysis_valid_token(self):
        """Prueba 1: Análisis léxico de token válido"""
        result = self.analyzer.lexical_analysis(self.valid_token_hs256)
        
        self.assertEqual(len(result['tokens']), 5)
        self.assertEqual(result['tokens'][0]['type'], 'HEADER')
        self.assertEqual(result['tokens'][1]['type'], 'SEPARATOR')
        self.assertEqual(result['tokens'][2]['type'], 'PAYLOAD')
        self.assertEqual(result['tokens'][3]['type'], 'SEPARATOR')
        self.assertEqual(result['tokens'][4]['type'], 'SIGNATURE')
        print("✅ Prueba 1: Análisis léxico - PASÓ")
    
    def test_lexical_analysis_malformed_token(self):
        """Prueba 2: Token malformado (solo 2 partes)"""
        malformed_token = 'eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0In0'
        
        with self.assertRaises(ValueError) as context:
            self.analyzer.lexical_analysis(malformed_token)
        
        self.assertIn('3 partes', str(context.exception))
        print("✅ Prueba 2: Token malformado - PASÓ")
    
    # ========== PRUEBAS FASE 4: DECODIFICACIÓN ==========
    
    def test_base64url_decode_valid(self):
        """Prueba 3: Decodificación Base64URL válida"""
        encoded = 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9'
        decoded = self.analyzer.base64url_decode(encoded)
        
        self.assertIsInstance(decoded, dict)
        self.assertEqual(decoded['alg'], 'HS256')
        self.assertEqual(decoded['typ'], 'JWT')
        print("✅ Prueba 3: Decodificación Base64URL - PASÓ")
    
    def test_decode_jwt_valid_token(self):
        """Prueba 4: Decodificación completa de JWT"""
        result = self.analyzer.decode_jwt(self.valid_token_hs256)
        
        self.assertIn('header', result)
        self.assertIn('payload', result)
        self.assertIn('signature', result)
        self.assertEqual(result['header']['alg'], 'HS256')
        print("✅ Prueba 4: Decodificación JWT completa - PASÓ")
    
    # ========== PRUEBAS FASE 2: ANÁLISIS SINTÁCTICO ==========
    
    def test_syntactic_analysis_valid(self):
        """Prueba 5: Análisis sintáctico válido"""
        header = {'alg': 'HS256', 'typ': 'JWT'}
        payload = {'sub': '1234567890', 'name': 'John Doe'}
        
        result = self.analyzer.syntactic_analysis(header, payload)
        
        self.assertTrue(result['valid'])
        self.assertEqual(len(result['errors']), 0)
        print("✅ Prueba 5: Análisis sintáctico válido - PASÓ")
    
    def test_syntactic_analysis_invalid_header(self):
        """Prueba 6: Header inválido (no es objeto)"""
        header = "invalid"
        payload = {'sub': '1234567890'}
        
        result = self.analyzer.syntactic_analysis(header, payload)
        
        self.assertFalse(result['valid'])
        self.assertGreater(len(result['errors']), 0)
        print("✅ Prueba 6: Header inválido detectado - PASÓ")
    
    # ========== PRUEBAS FASE 3: ANÁLISIS SEMÁNTICO ==========
    
    def test_semantic_analysis_valid(self):
        """Prueba 7: Análisis semántico válido"""
        header = {'alg': 'HS256', 'typ': 'JWT'}
        payload = {
            'sub': '1234567890',
            'name': 'John Doe',
            'iat': 1516239022,
            'exp': 9999999999
        }
        
        result = self.analyzer.semantic_analysis(header, payload)
        
        self.assertTrue(result['valid'])
        self.assertGreater(len(result['symbol_table']), 0)
        print("✅ Prueba 7: Análisis semántico válido - PASÓ")
    
    def test_semantic_analysis_missing_alg(self):
        """Prueba 8: Campo obligatorio 'alg' faltante"""
        header = {'typ': 'JWT'}  # Sin 'alg'
        payload = {'sub': '1234567890'}
        
        result = self.analyzer.semantic_analysis(header, payload)
        
        self.assertFalse(result['valid'])
        self.assertTrue(any('alg' in error for error in result['errors']))
        print("✅ Prueba 8: Campo 'alg' faltante detectado - PASÓ")
    
    def test_semantic_analysis_expired_token(self):
        """Prueba 9: Token expirado"""
        header = {'alg': 'HS256', 'typ': 'JWT'}
        payload = {
            'sub': '1234567890',
            'exp': 1516239022  # Fecha pasada
        }
        
        result = self.analyzer.semantic_analysis(header, payload)
        
        self.assertFalse(result['valid'])
        self.assertTrue(any('expirado' in error.lower() for error in result['errors']))
        print("✅ Prueba 9: Token expirado detectado - PASÓ")
    
    def test_semantic_analysis_invalid_exp_type(self):
        """Prueba 10: Tipo de dato incorrecto en 'exp'"""
        header = {'alg': 'HS256', 'typ': 'JWT'}
        payload = {
            'sub': '1234567890',
            'exp': '9999999999'  # String en lugar de número
        }
        
        result = self.analyzer.semantic_analysis(header, payload)
        
        self.assertFalse(result['valid'])
        self.assertTrue(any('exp' in error and 'numérico' in error for error in result['errors']))
        print("✅ Prueba 10: Tipo incorrecto en 'exp' detectado - PASÓ")
    
    # ========== PRUEBAS FASE 5: CODIFICACIÓN ==========
    
    def test_encode_jwt_hs256(self):
        """Prueba 11: Codificación JWT HS256"""
        header = {'alg': 'HS256', 'typ': 'JWT'}
        payload = {
            'sub': '1234567890',
            'name': 'Test User',
            'iat': 1516239022,
            'exp': 9999999999
        }
        
        result = self.analyzer.encode_jwt(header, payload, self.secret_key)
        
        self.assertIn('token', result)
        self.assertEqual(result['algorithm'], 'HS256')
        self.assertEqual(len(result['token'].split('.')), 3)
        print("✅ Prueba 11: Codificación JWT HS256 - PASÓ")
    
    def test_encode_jwt_without_alg(self):
        """Prueba 12: Codificación sin campo 'alg'"""
        header = {'typ': 'JWT'}  # Sin 'alg'
        payload = {'sub': '1234567890'}
        
        with self.assertRaises(ValueError) as context:
            self.analyzer.encode_jwt(header, payload, self.secret_key)
        
        self.assertIn('alg', str(context.exception))
        print("✅ Prueba 12: Error sin 'alg' detectado - PASÓ")
    
    # ========== PRUEBAS FASE 6: VERIFICACIÓN CRIPTOGRÁFICA ==========
    
    def test_verify_signature_valid(self):
        """Prueba 13: Verificación de firma válida"""
        decoded = self.analyzer.decode_jwt(self.valid_token_hs256)
        result = self.analyzer.verify_signature(
            self.valid_token_hs256,
            self.secret_key,
            decoded['header'],
            decoded['payload']
        )
        
        self.assertTrue(result['valid'])
        self.assertEqual(result['algorithm'], 'HS256')
        print("✅ Prueba 13: Firma válida verificada - PASÓ")
    
    def test_verify_signature_invalid(self):
        """Prueba 14: Verificación de firma inválida"""
        invalid_token = self.valid_token_hs256[:-10] + 'InvalidSig'
        decoded = self.analyzer.decode_jwt(self.valid_token_hs256)
        
        result = self.analyzer.verify_signature(
            invalid_token,
            self.secret_key,
            decoded['header'],
            decoded['payload']
        )
        
        self.assertFalse(result['valid'])
        print("✅ Prueba 14: Firma inválida detectada - PASÓ")
    
    def test_verify_signature_wrong_secret(self):
        """Prueba 15: Verificación con clave incorrecta"""
        decoded = self.analyzer.decode_jwt(self.valid_token_hs256)
        wrong_secret = 'wrong-secret-key'
        
        result = self.analyzer.verify_signature(
            self.valid_token_hs256,
            wrong_secret,
            decoded['header'],
            decoded['payload']
        )
        
        self.assertFalse(result['valid'])
        print("✅ Prueba 15: Clave incorrecta detectada - PASÓ")
    
    # ========== PRUEBAS ANÁLISIS COMPLETO ==========
    
    def test_analyze_complete_valid_token(self):
        """Prueba 16: Análisis completo de token válido"""
        result = self.analyzer.analyze_complete(self.valid_token_hs256, self.secret_key)
        
        self.assertTrue(result['success'])
        self.assertTrue(result['is_valid'])
        self.assertIn('phases', result)
        self.assertEqual(result['summary']['total_errors'], 0)
        print("✅ Prueba 16: Análisis completo exitoso - PASÓ")
    
    def test_analyze_complete_malformed_token(self):
        """Prueba 17: Análisis de token malformado"""
        malformed_token = 'invalid.token'
        
        result = self.analyzer.analyze_complete(malformed_token, self.secret_key)
        
        self.assertFalse(result['success'])
        self.assertIn('error', result)
        print("✅ Prueba 17: Token malformado detectado en análisis completo - PASÓ")
    
    # ========== PRUEBAS DE ALGORITMOS ==========
    
    def test_encode_decode_hs384(self):
        """Prueba 18: Codificación y decodificación HS384"""
        header = {'alg': 'HS384', 'typ': 'JWT'}
        payload = {'sub': '1234567890', 'name': 'Test', 'exp': 9999999999}
        secret = 'your-384-bit-secret'
        
        # Codificar
        encoded_result = self.analyzer.encode_jwt(header, payload, secret)
        token = encoded_result['token']
        
        # Decodificar
        decoded = self.analyzer.decode_jwt(token)
        
        self.assertEqual(decoded['header']['alg'], 'HS384')
        self.assertEqual(decoded['payload']['sub'], '1234567890')
        print("✅ Prueba 18: HS384 codificación/decodificación - PASÓ")
    
    def test_encode_decode_hs512(self):
        """Prueba 19: Codificación y decodificación HS512"""
        header = {'alg': 'HS512', 'typ': 'JWT'}
        payload = {'sub': '1234567890', 'name': 'Test', 'exp': 9999999999}
        secret = 'your-512-bit-secret'
        
        # Codificar
        encoded_result = self.analyzer.encode_jwt(header, payload, secret)
        token = encoded_result['token']
        
        # Decodificar y verificar
        decoded = self.analyzer.decode_jwt(token)
        verify_result = self.analyzer.verify_signature(token, secret, decoded['header'], decoded['payload'])
        
        self.assertEqual(decoded['header']['alg'], 'HS512')
        self.assertTrue(verify_result['valid'])
        print("✅ Prueba 19: HS512 codificación/verificación - PASÓ")
    
    def test_base64url_encode_decode_cycle(self):
        """Prueba 20: Ciclo completo de codificación/decodificación Base64URL"""
        original_data = {'test': 'data', 'number': 123, 'boolean': True}
        
        # Codificar
        import json
        json_str = json.dumps(original_data)
        encoded = self.analyzer.base64url_encode(json_str)
        
        # Decodificar
        decoded = self.analyzer.base64url_decode(encoded)
        
        self.assertEqual(decoded, original_data)
        print("✅ Prueba 20: Ciclo Base64URL completo - PASÓ")


def run_tests():
    """Ejecutar todas las pruebas"""
    print("\n" + "="*60)
    print("  🧪 EJECUTANDO SUITE DE PRUEBAS - ANALIZADOR JWT")
    print("="*60 + "\n")
    
    # Crear suite de pruebas
    loader = unittest.TestLoader()
    suite = loader.loadTestsFromTestCase(TestJWTAnalyzer)
    
    # Ejecutar con verbosidad
    runner = unittest.TextTestRunner(verbosity=2)
    result = runner.run(suite)
    
    # Resumen
    print("\n" + "="*60)
    print("  📊 RESUMEN DE PRUEBAS")
    print("="*60)
    print(f"✅ Pruebas exitosas: {result.testsRun - len(result.failures) - len(result.errors)}")
    print(f"❌ Pruebas fallidas: {len(result.failures)}")
    print(f"⚠️  Errores: {len(result.errors)}")
    print(f"📈 Total de pruebas: {result.testsRun}")
    
    if result.wasSuccessful():
        print("\n🎉 ¡TODAS LAS PRUEBAS PASARON EXITOSAMENTE!")
    else:
        print("\n⚠️  Algunas pruebas fallaron. Revisa los detalles arriba.")
    
    print("="*60 + "\n")
    
    return result


if __name__ == '__main__':
    run_tests()