from pymongo import MongoClient
from dotenv import load_dotenv
import os

# Cargar variables de entorno
load_dotenv()

# Obtener URI
MONGODB_URI = os.getenv('MONGODB_URI')

print("🔗 Intentando conectar a MongoDB...")
print(f"URI (sin contraseña): {MONGODB_URI.split('@')[1] if '@' in MONGODB_URI else 'ERROR'}")

try:
    # Conectar
    client = MongoClient(MONGODB_URI)
    
    # Probar conexión
    client.admin.command('ping')
    
    print("¡CONEXIÓN EXITOSA!")
    
    # Mostrar bases de datos
    print("\n Bases de datos disponibles:")
    for db_name in client.list_database_names():
        print(f"  - {db_name}")
    
    # Acceder a nuestra base de datos
    db = client.jwt_analyzer
    print(f"\n Base de datos seleccionada: jwt_analyzer")
    
    # Listar colecciones
    print("\n Colecciones en jwt_analyzer:")
    collections = db.list_collection_names()
    if collections:
        for col in collections:
            print(f"  - {col}")
    else:
        print("  (vacía - se crearán al insertar datos)")
    
    # Insertar documento de prueba
    print("\n Insertando documento de prueba...")
    test_collection = db.test_connection
    result = test_collection.insert_one({
        "message": "Conexión exitosa",
        "status": "ok",
        "test": True
    })
    print(f" Documento insertado con ID: {result.inserted_id}")
    
    # Leer documento
    print("\n Leyendo documento...")
    doc = test_collection.find_one({"test": True})
    print(f" Documento encontrado: {doc}")
    
    # Eliminar documento de prueba
    print("\n Eliminando documento de prueba...")
    test_collection.delete_one({"test": True})
    print(" Documento eliminado")
    
    print("\n ¡TODO FUNCIONÓ PERFECTAMENTE!")
    print(" MongoDB está listo para usar")
    
    client.close()
    
except Exception as e:
    print(f"\n ERROR: {e}")
    print("\n Verifica:")
    print("  1. Tu cadena de conexión en .env")
    print("  2. Que reemplazaste <password> con tu contraseña real")
    print("  3. Que tu IP está en la lista de acceso en MongoDB Atlas")
    print("  4. Que tienes internet activo")