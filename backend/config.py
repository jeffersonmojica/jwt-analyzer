import os
from dotenv import load_dotenv

load_dotenv()

class Config:
    MONGODB_URI = os.getenv('MONGODB_URI')
    SECRET_KEY = os.getenv('SECRET_KEY', '1234')
    JWT_SECRET_KEY = os.getenv('JWT_SECRET_KEY', '1234')
    FLASK_ENV = os.getenv('FLASK_ENV', 'production')
    
    # Opciones SSL para MongoDB
    MONGODB_OPTIONS = {
        'tls': True,
        'tlsAllowInvalidCertificates': True,
        'serverSelectionTimeoutMS': 5000,
        'connectTimeoutMS': 10000,
        'socketTimeoutMS': 10000,
    }