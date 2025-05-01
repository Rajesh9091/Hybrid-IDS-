"""
Database models for the Network Intrusion Detection System
"""
import os
import json
from datetime import datetime
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy.dialects.postgresql import JSON

db = SQLAlchemy()

class DetectionSession(db.Model):
    """Model for a detection session, which represents a single analysis run"""
    __tablename__ = 'detection_sessions'
    
    id = db.Column(db.Integer, primary_key=True)
    file_name = db.Column(db.String(255), nullable=True)  # Original file name, if available
    total_records = db.Column(db.Integer, nullable=False)
    normal_count = db.Column(db.Integer, nullable=False)
    attack_count = db.Column(db.Integer, nullable=False)
    accuracy = db.Column(db.Float, nullable=True)
    precision = db.Column(db.Float, nullable=True)
    recall = db.Column(db.Float, nullable=True)
    f1_score = db.Column(db.Float, nullable=True)
    confusion_matrix = db.Column(JSON, nullable=True)
    attack_types = db.Column(JSON, nullable=True)  # Stored as JSON: {"DoS": 5, "Probe": 3, ...}
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    
    # Relationship with detected anomalies
    anomalies = db.relationship('DetectedAnomaly', backref='session', lazy=True, cascade="all, delete-orphan")
    
    def __repr__(self):
        return f"<DetectionSession id={self.id}, attacks={self.attack_count}, normal={self.normal_count}>"
    
    @staticmethod
    def from_results(results, file_name=None):
        """Create a DetectionSession from detection results with proper type conversion"""
        try:
            # Ensure numeric values are proper Python types
            total_records = int(results.get('total_records', 0))
            normal_count = int(results.get('normal_count', 0))
            attack_count = int(results.get('attack_count', 0))
            
            # Convert float values
            accuracy = float(results.get('accuracy', 0.0)) if results.get('accuracy') is not None else None
            precision = float(results.get('precision', 0.0)) if results.get('precision') is not None else None
            recall = float(results.get('recall', 0.0)) if results.get('recall') is not None else None
            f1_score = float(results.get('f1_score', 0.0)) if results.get('f1_score') is not None else None
            
            # Ensure JSON serializable data
            confusion_matrix = results.get('confusion_matrix')
            if confusion_matrix is not None:
                # Convert any numpy arrays to lists
                confusion_matrix = [[float(cell) for cell in row] for row in confusion_matrix]
            
            # Ensure attack types are serializable
            attack_types = results.get('attack_types')
            if attack_types is not None:
                # Convert to standard Python dict with string keys and int values
                attack_types = {str(k): int(v) for k, v in attack_types.items()}
            
            session = DetectionSession(
                file_name=file_name,
                total_records=total_records,
                normal_count=normal_count,
                attack_count=attack_count,
                accuracy=accuracy,
                precision=precision,
                recall=recall,
                f1_score=f1_score,
                confusion_matrix=confusion_matrix,
                attack_types=attack_types
            )
            
            return session
        except Exception as e:
            print(f"Error in from_results: {str(e)}")
            # Fall back to a basic session if conversion fails
            return DetectionSession(
                file_name=file_name,
                total_records=0,
                normal_count=0,
                attack_count=0
            )

    def to_dict(self):
        """Convert the model to a dictionary ensuring all values are JSON serializable"""
        try:
            # Convert all values to standard Python types
            return {
                'id': int(self.id),
                'file_name': str(self.file_name) if self.file_name else None,
                'total_records': int(self.total_records),
                'normal_count': int(self.normal_count),
                'attack_count': int(self.attack_count),
                'accuracy': float(self.accuracy) if self.accuracy is not None else None,
                'precision': float(self.precision) if self.precision is not None else None,
                'recall': float(self.recall) if self.recall is not None else None,
                'f1_score': float(self.f1_score) if self.f1_score is not None else None,
                'confusion_matrix': self.confusion_matrix,  # Already converted to standard types in from_results
                'attack_types': self.attack_types,  # Already converted to standard types in from_results
                'created_at': self.created_at.isoformat() if self.created_at else None,
            }
        except Exception as e:
            print(f"Error in to_dict: {str(e)}")
            # Provide a safe fallback
            return {
                'id': self.id,
                'error': 'Could not fully serialize object',
                'total_records': 0,
                'normal_count': 0,
                'attack_count': 0
            }

class DetectedAnomaly(db.Model):
    """Model for storing individual detected anomalies"""
    __tablename__ = 'detected_anomalies'
    
    id = db.Column(db.Integer, primary_key=True)
    session_id = db.Column(db.Integer, db.ForeignKey('detection_sessions.id'), nullable=False)
    record_index = db.Column(db.Integer, nullable=False)  # Index/position in the original dataset
    anomaly_score = db.Column(db.Float, nullable=False)
    attack_type = db.Column(db.String(50), nullable=True)  # Could be NULL if not classified
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    
    def __repr__(self):
        return f"<DetectedAnomaly id={self.id}, score={self.anomaly_score}, type={self.attack_type}>"
    
    def to_dict(self):
        """Convert the model to a dictionary ensuring all values are JSON serializable"""
        try:
            return {
                'id': int(self.id),
                'session_id': int(self.session_id),
                'record_index': int(self.record_index),
                'anomaly_score': float(self.anomaly_score),
                'attack_type': str(self.attack_type) if self.attack_type else None,
                'created_at': self.created_at.isoformat() if self.created_at else None
            }
        except Exception as e:
            print(f"Error in anomaly to_dict: {str(e)}")
            return {
                'id': self.id,
                'error': 'Could not fully serialize anomaly object'
            }
