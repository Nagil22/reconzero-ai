import sys
import os

# Add parent directory to path to import app
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

try:
    from app import app
except ImportError:
    # Fallback if import fails
    from flask import Flask
    app = Flask(__name__)
    
    @app.route('/')
    def hello():
        return "ReConZero AI - Import Error. Check deployment configuration."

# Export for Vercel
application = app

if __name__ == "__main__":
    app.run()
