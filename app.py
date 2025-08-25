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
app.config['MAX_CONTENT_LENGTH'] = 100 * 1024 * 1024  # 100MB max file size

@app.route('/analyze', methods=['POST'])
def analyze_apk():
    if 'file' not in request.files:
        return jsonify({'error': 'No file uploaded'}), 400
    
    file = request.files['file']
    if file.filename == '':
        return jsonify({'error': 'No file selected'}), 400

    # Check if file is an APK
    if not file.filename.lower().endswith('.apk'):
        return jsonify({'error': 'File must be an APK'}), 400

    # Save uploaded file temporarily
    with tempfile.NamedTemporaryFile(delete=False, suffix='.apk') as tmp:
        file.save(tmp.name)
        tmp_path = tmp.name

    try:
        # Import and use your existing analyzer
        from apk_checker import generate_report
        result = generate_report(tmp_path)
        return jsonify(result)
    except Exception as e:
        logger.error(f"Error during APK analysis: {str(e)}")
        logger.error(traceback.format_exc())
        return jsonify({'error': 'Failed to analyse APK', 'details': str(e)}), 500
    finally:
        # Clean up temporary file
        try:
            os.unlink(tmp_path)
        except:
            pass

@app.route('/health', methods=['GET'])
def health_check():
    try:
        from apk_checker import load_model
        model = load_model()
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
    app.run(host='0.0.0.0', port=5000, debug=False)