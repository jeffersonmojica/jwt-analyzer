from flask import Flask, request, jsonify, send_from_directory
from flask_cors import CORS
from config import Config
from models import TokenModel, AnalysisModel, TestCaseModel
from jwt_analyzer import JWTAnalyzer
import os

app = Flask(__name__, static_folder='../frontend', static_url_path='')
app.config.from_object(Config)
CORS(app)

# Inicializar casos de prueba
TestCaseModel.initialize_test_cases()

# ============== RUTAS DE LA API ==============

@app.route('/')
def index():
    """Servir página principal"""
    return send_from_directory(app.static_folder, 'index.html')

@app.route('/api/health', methods=['GET'])
def health_check():
    """Verificar estado del servidor"""
    return jsonify({
        'status': 'ok',
        'message': 'JWT Analyzer API funcionando correctamente'
    })
@app.route('/api/analyze', methods=['POST'])
def analyze_jwt():
    """
    Endpoint principal: Analizar JWT completo
    """
    try:
        data = request.get_json()
        jwt_token = data.get('token', '').strip()
        secret_key = data.get('secret', '')
        
        if not jwt_token:
            return jsonify({
                'success': False,
                'error': 'Token JWT es requerido'
            }), 400
        
        if not secret_key:
            return jsonify({
                'success': False,
                'error': 'Clave secreta es requerida'
            }), 400
        
        # Crear instancia del analizador
        analyzer = JWTAnalyzer()
        
        # Análisis completo
        result = analyzer.analyze_complete(jwt_token, secret_key)
        
        # Guardar en MongoDB
        if result['success']:
            analysis_data = {
                'token': jwt_token[:50] + '...' if len(jwt_token) > 50 else jwt_token,
                'secret_used': secret_key,
                'is_valid': result['is_valid'],
                'phases': result['phases'],
                'summary': result['summary']
            }
            analysis_id = AnalysisModel.save_analysis(analysis_data)
            result['analysis_id'] = analysis_id
        
        return jsonify(result)
    
    except Exception as e:
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500

@app.route('/api/encode', methods=['POST'])
def encode_jwt():
    """
    Endpoint: Generar (codificar) nuevo JWT
    """
    try:
        data = request.get_json()
        header = data.get('header', {})
        payload = data.get('payload', {})
        secret_key = data.get('secret', '')
        
        if not header:
            return jsonify({
                'success': False,
                'error': 'Header es requerido'
            }), 400
        
        if not payload:
            return jsonify({
                'success': False,
                'error': 'Payload es requerido'
            }), 400
        
        if not secret_key:
            return jsonify({
                'success': False,
                'error': 'Clave secreta es requerida'
            }), 400
        
        # Crear instancia del analizador
        analyzer = JWTAnalyzer()
        
        # Codificar JWT
        result = analyzer.encode_jwt(header, payload, secret_key)
        
        # Guardar token generado en MongoDB
        token_data = {
            'token': result['token'],
            'header': header,
            'payload': payload,
            'algorithm': result['algorithm'],
            'type': 'generated'
        }
        token_id = TokenModel.save_token(token_data)
        
        return jsonify({
            'success': True,
            'token': result['token'],
            'header': result['header'],
            'payload': result['payload'],
            'algorithm': result['algorithm'],
            'token_id': token_id
        })
    
    except Exception as e:
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500

@app.route('/api/test-cases', methods=['GET'])
def get_test_cases():
    """
    Obtener todos los casos de prueba
    """
    try:
        category = request.args.get('category', None)
        
        if category:
            test_cases = TestCaseModel.get_test_cases_by_category(category)
        else:
            test_cases = TestCaseModel.get_all_test_cases()
        
        return jsonify({
            'success': True,
            'test_cases': test_cases,
            'total': len(test_cases)
        })
    
    except Exception as e:
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500

@app.route('/api/history', methods=['GET'])
def get_analysis_history():
    """
    Obtener historial de análisis
    """
    try:
        limit = int(request.args.get('limit', 50))
        analyses = AnalysisModel.get_all_analysis(limit)
        
        return jsonify({
            'success': True,
            'analyses': analyses,
            'total': len(analyses)
        })
    
    except Exception as e:
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500

@app.route('/api/tokens', methods=['GET'])
def get_tokens():
    """
    Obtener todos los tokens guardados
    """
    try:
        limit = int(request.args.get('limit', 50))
        tokens = TokenModel.get_all_tokens(limit)
        
        return jsonify({
            'success': True,
            'tokens': tokens,
            'total': len(tokens)
        })
    
    except Exception as e:
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500

@app.route('/api/statistics', methods=['GET'])
def get_statistics():
    """
    Obtener estadísticas del sistema
    """
    try:
        stats = AnalysisModel.get_statistics()
        
        return jsonify({
            'success': True,
            'statistics': stats
        })
    
    except Exception as e:
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500

@app.route('/api/validate', methods=['POST'])
def quick_validate():
    """
    Validación rápida de JWT (solo verificar firma)
    """
    try:
        data = request.get_json()
        jwt_token = data.get('token', '').strip()
        secret_key = data.get('secret', '')
        
        if not jwt_token or not secret_key:
            return jsonify({
                'success': False,
                'error': 'Token y clave secreta son requeridos'
            }), 400
        
        analyzer = JWTAnalyzer()
        decoded = analyzer.decode_jwt(jwt_token)
        signature_result = analyzer.verify_signature(
            jwt_token, 
            secret_key, 
            decoded['header'], 
            decoded['payload']
        )
        
        return jsonify({
            'success': True,
            'valid': signature_result['valid'],
            'algorithm': signature_result['algorithm'],
            'message': signature_result.get('message', '')
        })
    
    except Exception as e:
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500

# ============== MANEJO DE ERRORES ==============

@app.errorhandler(404)
def not_found(error):
    return jsonify({
        'success': False,
        'error': 'Endpoint no encontrado'
    }), 404

@app.errorhandler(500)
def internal_error(error):
    return jsonify({
        'success': False,
        'error': 'Error interno del servidor'
    }), 500

if __name__ == '__main__':
    port = int(os.environ.get('PORT', 5000))
    app.run(host='0.0.0.0', port=port, debug=Config.FLASK_ENV == 'development')