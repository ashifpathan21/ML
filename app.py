# app.py
from flask import Flask, request, jsonify
import tempfile
import os
import sys
import traceback
import logging

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Add the current directory to Python path
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

app = Flask(__name__)
# Allow bigger files (up to 300 MB)
app.config['MAX_CONTENT_LENGTH'] = 300 * 1024 * 1024  

# Try to import dependencies at startup
try:
    import joblib
    from androguard.core.apk import APK
    from cryptography import x509
    from cryptography.hazmat.backends import default_backend
    logger.info("✓ All dependencies imported successfully")
except ImportError as e:
    logger.error(f"✗ Import error: {e}")
    logger.error(traceback.format_exc())

# Try to load the model at startup
try:
    from apk_checker import load_model
    model = load_model()
    if model:
        logger.info("✓ Model loaded successfully")
    else:
        logger.error("✗ Failed to load model")
except Exception as e:
    logger.error(f"✗ Error loading model: {e}")
    logger.error(traceback.format_exc())
    model = None


@app.route('/analyze', methods=['POST'])
def analyze_apk():
    try:
        if 'file' not in request.files:
            return jsonify({'error': 'No file uploaded'}), 400
        
        file = request.files['file']
        if file.filename == '':
            return jsonify({'error': 'No file selected'}), 400

        if not file.filename.lower().endswith('.apk'):
            return jsonify({'error': 'File must be an APK'}), 400

        # Save uploaded file efficiently (streaming, avoids big RAM usage)
        with tempfile.NamedTemporaryFile(delete=False, suffix='.apk') as tmp:
            for chunk in file.stream:
                tmp.write(chunk)
            tmp_path = tmp.name

        try:
            from apk_checker import generate_report
            result = generate_report(tmp_path)
            return jsonify(result)
        except Exception as e:
            logger.error(f"Error during APK analysis: {str(e)}")
            logger.error(traceback.format_exc())
            return jsonify({'error': 'Failed to analyse APK', 'details': str(e)}), 500
        finally:
            try:
                os.unlink(tmp_path)
            except:
                pass

    except Exception as e:
        logger.error(f"Unexpected error in analyze_apk: {str(e)}")
        logger.error(traceback.format_exc())
        return jsonify({'error': 'Unexpected server error'}), 500


@app.route('/health', methods=['GET'])
def health_check():
    try:
        return jsonify({
            'status': 'healthy', 
            'model_loaded': model is not None
        })
    except Exception as e:
        return jsonify({
            'status': 'error', 
            'details': str(e)
        }), 500


if __name__ == '__main__':
    logger.info("Starting Flask application")
    # Increase timeout if running via gunicorn: gunicorn -w 4 -b 0.0.0.0:5000 app:app --timeout 300
    app.run(host='0.0.0.0', port=5000, debug=False)
