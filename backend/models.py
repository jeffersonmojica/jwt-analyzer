from datetime import datetime
from pymongo import MongoClient
from pymongo.server_api import ServerApi
from config import Config
import certifi

# Crear cliente con opciones SSL específicas
client = MongoClient(
    Config.MONGODB_URI,
    server_api=ServerApi('1'),
    tlsCAFile=certifi.where(),
    tls=True,
    tlsAllowInvalidCertificates=True,
    serverSelectionTimeoutMS=5000,
    connectTimeoutMS=10000,
    socketTimeoutMS=10000
)

db = client.jwt_analyzer

# Colecciones
tokens_collection = db.tokens
analysis_collection = db.analysis_results
test_cases_collection = db.test_cases


class TokenModel:
    @staticmethod
    def save_token(token_data):
        """Guardar token analizado"""
        token_data['created_at'] = datetime.utcnow()
        result = tokens_collection.insert_one(token_data)
        return str(result.inserted_id)
    
    @staticmethod
    def get_all_tokens(limit=50):
        """Obtener todos los tokens"""
        tokens = list(tokens_collection.find().sort('created_at', -1).limit(limit))
        for token in tokens:
            token['_id'] = str(token['_id'])
        return tokens
    
    @staticmethod
    def get_token_by_id(token_id):
        """Obtener token por ID"""
        from bson import ObjectId
        token = tokens_collection.find_one({'_id': ObjectId(token_id)})
        if token:
            token['_id'] = str(token['_id'])
        return token


class AnalysisModel:
    @staticmethod
    def save_analysis(analysis_data):
        """Guardar resultado de análisis"""
        analysis_data['created_at'] = datetime.utcnow()
        result = analysis_collection.insert_one(analysis_data)
        return str(result.inserted_id)
    
    @staticmethod
    def get_all_analysis(limit=50):
        """Obtener todos los análisis"""
        analyses = list(analysis_collection.find().sort('created_at', -1).limit(limit))
        for analysis in analyses:
            analysis['_id'] = str(analysis['_id'])
        return analyses
    
    @staticmethod
    def get_statistics():
        """Obtener estadísticas"""
        total = analysis_collection.count_documents({})
        valid = analysis_collection.count_documents({'is_valid': True})
        invalid = analysis_collection.count_documents({'is_valid': False})
        
        return {
            'total_analyses': total,
            'valid_tokens': valid,
            'invalid_tokens': invalid,
            'success_rate': (valid / total * 100) if total > 0 else 0
        }


class TestCaseModel:
    @staticmethod
    def initialize_test_cases():
        """Inicializar casos de prueba en la BD"""
        if test_cases_collection.count_documents({}) == 0:
            test_cases = [
                {
                    'name': 'Token Válido HS256',
                    'description': 'Token correctamente formado con algoritmo HS256',
                    'token': 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyLCJleHAiOjk5OTk5OTk5OTl9.Vg30C57s3l90JNap_VgMhKZjfc-p7SoBXaSAy8c28HA',
                    'secret': 'your-256-bit-secret',
                    'expected_result': 'valid',
                    'category': 'valid',
                    'created_at': datetime.utcnow()
                },
                {
                    'name': 'Token Válido HS384',
                    'description': 'Token con algoritmo HS384',
                    'token': 'eyJhbGciOiJIUzM4NCIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkphbmUgRG9lIiwiaWF0IjoxNTE2MjM5MDIyLCJleHAiOjk5OTk5OTk5OTl9.DiHJZvNzL8FM5u30bXGQKPr6E_33l_v6cLgB7OQsKqy-N2CmzG9P6t0sSrXChqrp',
                    'secret': 'your-384-bit-secret',
                    'expected_result': 'valid',
                    'category': 'valid',
                    'created_at': datetime.utcnow()
                },
                {
                    'name': 'Token Expirado',
                    'description': 'Token con fecha de expiración pasada',
                    'token': 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyLCJleHAiOjE1MTYyMzkwMjJ9.4Adcj0mCKmXg0K4RbFb3jg-CP5OBNLW3aAOG0WvMm9s',
                    'secret': 'your-256-bit-secret',
                    'expected_result': 'expired',
                    'category': 'temporal',
                    'created_at': datetime.utcnow()
                },
                {
                    'name': 'Token Malformado - Sin Firma',
                    'description': 'Token incompleto (solo 2 partes)',
                    'token': 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIn0',
                    'secret': 'your-256-bit-secret',
                    'expected_result': 'malformed',
                    'category': 'syntax',
                    'created_at': datetime.utcnow()
                },
                {
                    'name': 'Token con Firma Inválida',
                    'description': 'Firma no coincide con el contenido',
                    'token': 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyLCJleHAiOjk5OTk5OTk5OTl9.InvalidSignatureHere123456789',
                    'secret': 'your-256-bit-secret',
                    'expected_result': 'invalid_signature',
                    'category': 'cryptographic',
                    'created_at': datetime.utcnow()
                },
                {
                    'name': 'Token sin Campo "alg"',
                    'description': 'Header sin algoritmo especificado',
                    'token': 'eyJ0eXAiOiJKV1QifQ.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIn0.signature',
                    'secret': 'your-256-bit-secret',
                    'expected_result': 'missing_required_field',
                    'category': 'semantic',
                    'created_at': datetime.utcnow()
                },
                {
                    'name': 'Token con Tipos Incorrectos',
                    'description': 'Claim "exp" como string en lugar de número',
                    'token': 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiZXhwIjoiMTIzNDU2Nzg5MCJ9.signature',
                    'secret': 'your-256-bit-secret',
                    'expected_result': 'type_error',
                    'category': 'semantic',
                    'created_at': datetime.utcnow()
                }
            ]
            test_cases_collection.insert_many(test_cases)
    
    @staticmethod
    def get_all_test_cases():
        """Obtener todos los casos de prueba"""
        cases = list(test_cases_collection.find())
        for case in cases:
            case['_id'] = str(case['_id'])
        return cases
    
    @staticmethod
    def get_test_cases_by_category(category):
        """Obtener casos por categoría"""
        cases = list(test_cases_collection.find({'category': category}))
        for case in cases:
            case['_id'] = str(case['_id'])
        return cases