"""
AI-Driven Hybrid Approach for Intrusion Detection
Demo script that automatically processes sample data
"""
import os
import sys
import numpy as np
from data_processor import DataProcessor
from model_handler import ModelHandler

def print_header():
    """Print application header"""
    print("\n" + "=" * 80)
    print("  AI-DRIVEN NETWORK INTRUSION DETECTION SYSTEM - AUTOMATED DEMO")
    print("=" * 80 + "\n")

def main():
    """Run automated demo"""
    print_header()
    
    # Initialize components
    print("Initializing data processor and model handler...")
    data_processor = DataProcessor()
    model_handler = ModelHandler()
    
    # Load sample data
    sample_file = "sample_network_data.csv"
    print(f"\nLoading sample data from {sample_file}...")
    
    if not os.path.exists(sample_file):
        print(f"Error: Sample file '{sample_file}' not found.")
        sys.exit(1)
    
    result = data_processor.load_data(sample_file)
    
    if not result:
        print("Error: Failed to load sample data.")
        sys.exit(1)
    
    # Display data info
    print("\nSAMPLE DATA INFORMATION:")
    data_info = data_processor.get_data_info()
    print(f"Records: {data_info['rows']:,}")
    print(f"Features: {data_info['columns']}")
    
    # Process data
    print("\nPreprocessing data...")
    processed_data = data_processor.preprocess_data()
    
    if processed_data is None:
        print("Error: Failed to process data.")
        sys.exit(1)
    
    # Run detection
    print("\nRunning intrusion detection...")
    try:
        results = model_handler.detect_intrusions(processed_data)
        
        print("\nDETECTION RESULTS:")
        print(f"Total records: {results['total_records']:,}")
        print(f"Normal traffic: {results['normal_count']:,} ({results['normal_count']/results['total_records']*100:.1f}%)")
        print(f"Detected intrusions: {results['attack_count']:,} ({results['attack_count']/results['total_records']*100:.1f}%)")
        
        if results['attack_count'] > 0:
            print("\nAttack Type Distribution:")
            for attack_type, count in results['attack_types'].items():
                print(f"- {attack_type}: {count:,} ({count/results['attack_count']*100:.1f}%)")
        
        print("\nMODEL PERFORMANCE METRICS:")
        if results['accuracy'] is not None:
            print(f"Accuracy: {results['accuracy']:.4f}")
            print(f"Precision: {results['precision']:.4f}")
            print(f"Recall: {results['recall']:.4f}")
            print(f"F1 Score: {results['f1_score']:.4f}")
            
            print("\nConfusion Matrix:")
            cm = results['confusion_matrix']
            print(f"               | Predicted Normal | Predicted Attack |")
            print(f"Actual Normal  |       {cm[0][0]:^10}  |       {cm[0][1]:^10}  |")
            print(f"Actual Attack  |       {cm[1][0]:^10}  |       {cm[1][1]:^10}  |")
        else:
            print("Metrics not available (no labeled data)")
        
        # Print some values from the anomaly scores
        print("\nSample Anomaly Scores (first 5 records):")
        for i, score in enumerate(results['anomaly_scores'][:5]):
            print(f"Record {i+1}: {score:.6f}")
            
    except Exception as e:
        print(f"Error during detection: {str(e)}")
        sys.exit(1)
    
    print("\nDemo completed successfully!")

if __name__ == "__main__":
    main()
