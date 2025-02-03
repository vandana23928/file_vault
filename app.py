from flask import Flask, render_template, request, send_file, after_this_request
from werkzeug.utils import secure_filename
from crypto import CryptoVault
import os
import logging

# Initialize Flask app
app = Flask(__name__)
app.config['UPLOAD_FOLDER'] = 'uploads'
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024  # 16MB limit
app.secret_key = os.urandom(24)

# Configure logging
logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger(__name__)

# Initialize CryptoVault
vault = CryptoVault()

def ensure_directories():
    """Ensure required directories exist"""
    directories = ['uploads', 'keys', 'static', 'templates']
    for directory in directories:
        if not os.path.exists(directory):
            os.makedirs(directory)

@app.route('/', methods=['GET', 'POST'])
def index():
    if request.method == 'POST':
        if 'file' not in request.files:
            return "No file selected", 400
            
        file = request.files['file']
        if file.filename == '':
            return "No file selected", 400
            
        operation = request.form.get('operation')
        use_password = request.form.get('use_password') == 'on'
        password = request.form.get('password') if use_password else None

        # Save uploaded file
        filename = secure_filename(file.filename)
        file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
        file.save(file_path)
        
        try:
            if operation == 'encrypt':
                result_path = vault.encrypt_file(file_path, "keys/public.pem", password)
            else:
                result_path = vault.decrypt_file(file_path, "keys/private.pem", password)

            @after_this_request
            def cleanup(response):
                try:
                    if os.path.exists(file_path):
                        os.remove(file_path)
                    if os.path.exists(result_path):
                        os.remove(result_path)
                except Exception as e:
                    logger.error(f"Cleanup error: {str(e)}")
                return response

            return send_file(
                result_path,
                as_attachment=True,
                download_name=os.path.basename(result_path)
            )

        except Exception as e:
            logger.error(f"Processing error: {str(e)}")
            if os.path.exists(file_path):
                try:
                    os.remove(file_path)
                except:
                    pass
            return f"Error processing file: {str(e)}", 400

    return render_template('index.html')

if __name__ == '__main__':
    ensure_directories()
    app.run(debug=True, host='0.0.0.0', port=5000)
