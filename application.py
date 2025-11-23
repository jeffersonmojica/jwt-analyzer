#!/usr/bin/env python
import sys
import os

# Get current directory
current_dir = os.path.dirname(os.path.abspath(__file__))
backend_dir = os.path.join(current_dir, 'backend')

# Add to path
sys.path.insert(0, current_dir)
sys.path.insert(0, backend_dir)

# Change to backend directory
try:
    os.chdir(backend_dir)
except:
    pass

# Import Flask app
from app import app as application

if __name__ == '__main__':
    application.run(host='0.0.0.0', port=8080)