import sys
import os

# Agregar backend al path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'backend'))

from backend.app import app as application

if __name__ == '__main__':
    application.run()
    