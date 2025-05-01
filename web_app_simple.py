"""
AI-Driven Hybrid Approach for Intrusion Detection
Web interface version - Simplified with better error handling
"""
from flask import Flask, render_template, request, jsonify, send_from_directory
import os
import json
import uuid
from datetime import datetime
from werkzeug.utils import secure_filename
from data_processor import DataProcessor
from model_handler import ModelHandler
from models import db, DetectionSession, DetectedAnomaly

app = Flask(__name__)
app.config['UPLOAD_FOLDER'] = 'uploads'
app.config['MAX_CONTENT_LENGTH'] = 50 * 1024 * 1024  # 50MB max file size
app.config['ALLOWED_EXTENSIONS'] = {'csv'}

# Database configuration
database_url = os.environ.get('DATABASE_URL')
if not database_url:
    raise ValueError("DATABASE_URL environment variable is not set!")

app.config['SQLALCHEMY_DATABASE_URI'] = database_url
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SQLALCHEMY_ENGINE_OPTIONS'] = {
    'pool_pre_ping': True,  # Check if connection is alive before using it
    'pool_recycle': 280,    # Recycle connections after 280 seconds
    'pool_timeout': 30,     # Connection timeout of 30 seconds
    'pool_size': 10,        # Maximum number of connections to keep
    'max_overflow': 15      # Maximum number of connections to create beyond pool_size
}

# Create uploads folder if it doesn't exist
os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)

# Initialize components
data_processor = DataProcessor()
model_handler = ModelHandler()
db.init_app(app)

def allowed_file(filename):
    """Check if the file extension is allowed"""
    return '.' in filename and \
           filename.rsplit('.', 1)[1].lower() in app.config['ALLOWED_EXTENSIONS']

@app.route('/')
def index():
    """Render main page using template"""
    return render_template('index.html')

@app.route('/upload', methods=['POST'])
def upload_file():
    """Handle file upload with improved error handling"""
    try:
        # Check if file part exists
        if 'file' not in request.files:
            return jsonify({"error": "No file part in the request"}), 400
        
        file = request.files['file']
        
        # Check if filename is empty
        if file.filename == '':
            return jsonify({"error": "No file selected"}), 400
            
        # Check if file type is allowed
        if not allowed_file(file.filename):
            return jsonify({"error": "File type not allowed. Please upload a CSV file."}), 400
            
        # Save file securely
        filename = secure_filename(file.filename)
        unique_filename = f"{uuid.uuid4()}_{filename}"
        file_path = os.path.join(app.config['UPLOAD_FOLDER'], unique_filename)
        
        try:
            file.save(file_path)
        except Exception as e:
            return jsonify({"error": f"Failed to save file: {str(e)}"}), 500
            
        # Process data
        try:
            if not data_processor.load_data(file_path):
                os.remove(file_path)
                return jsonify({"error": "Failed to load data from file"}), 400
                
            processed_data = data_processor.preprocess_data()
            if processed_data is None:
                os.remove(file_path)
                return jsonify({"error": "Failed to preprocess data"}), 500
                
            # Run detection
            results = model_handler.detect_intrusions(processed_data)
            
            # Save basic session info
            try:
                # Create a safe version of the results for JSON serialization
                safe_results = {
                    "total_records": int(results.get("total_records", 0)),
                    "normal_count": int(results.get("normal_count", 0)),
                    "attack_count": int(results.get("attack_count", 0)),
                    "accuracy": float(results.get("accuracy", 0.0)),
                    "precision": float(results.get("precision", 0.0)),
                    "recall": float(results.get("recall", 0.0)),
                    "f1_score": float(results.get("f1_score", 0.0)),
                    # Ensure confusion matrix is a list of lists of standard Python types
                    "confusion_matrix": [[float(val) for val in row] for row in results.get("confusion_matrix", [[0, 0], [0, 0]])],
                    # Only retain a few anomaly scores to prevent recursion issues
                    "anomaly_scores": [float(score) for score in results.get("anomaly_scores", [])[:5]],
                    # Ensure attack types are standard Python types
                    "attack_types": {str(k): int(v) for k, v in results.get("attack_types", {}).items()}
                }
                
                session = DetectionSession.from_results(safe_results, file_name=filename)
                db.session.add(session)
                db.session.commit()
                
                # No anomaly details for simplicity
                
                # Clean up
                os.remove(file_path)
                
                # Add session ID to results
                safe_results['session_id'] = int(session.id)
                
                return
