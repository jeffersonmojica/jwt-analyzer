from models import TestCaseModel, db
from pymongo import MongoClient
from dotenv import load_dotenv
import os

load_dotenv()

print(" Inicializando base de datos...")

# Verificar conexión
try:
    client = MongoClient(os.getenv('MONGODB_URI'))
    client.admin.command('ping')
    print(" Conectado a MongoDB")
except Exception as e:
    print(f" Error de conexión: {e}")
    exit(1)

# Limpiar colecciones existentes (opcional)
print("\n Limpiando colecciones...")
db.test_cases.delete_many({})
db.tokens.delete_many({})
db.analysis_results.delete_many({})
print(" Colecciones limpiadas")

# Inicializar casos de prueba
print("\n Creando casos de prueba...")
TestCaseModel.initialize_test_cases()

# Verificar
count = db.test_cases.count_documents({})
print(f" {count} casos de prueba creados")

# Mostrar casos
print("\n Casos de prueba en la base de datos:")
for case in db.test_cases.find():
    print(f"  - {case['name']}")

print("\n ¡Base de datos inicializada correctamente!")