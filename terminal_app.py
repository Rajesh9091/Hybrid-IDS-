"""
AI-Driven Hybrid Approach for Intrusion Detection
Terminal version of the application
"""
import os
import sys
import numpy as np
from data_processor import DataProcessor
from model_handler import ModelHandler

def clear_screen():
    """Clear the terminal screen"""
    os.system('cls' if os.name == 'nt' else 'clear')

def print_header():
    """Print application header"""
    print("\n" + "=" * 80)
    print("  AI-DRIVEN NETWORK INTRUSION DETECTION SYSTEM")
    print("  Terminal Interface")
    print("=" * 80 + "\n")

def print_menu():
    """Print the main menu"""
    print("\nMAIN MENU:")
    print("1. Load CSV file")
    print("2. Run intrusion detection")
    print("3. View dataset information")
    print("4. About")
    print("5. Exit")
    print("\nEnter your choice (1-5): ", end="")

def load_csv(data_processor):
    """Load a CSV file"""
    clear_screen()
    print_header()
    print("LOAD CSV FILE\n")
    
    print("Available sample file:")
    print("- sample_network_data.csv (sample NSL-KDD dataset)")
    print("\nEnter file path (or press Enter to use sample): ", end="")
    
    file_path = input().strip()
    if not file_path:
        file_path = "sample_network_data.csv"
    
    print(f"\nLoading {file_path}...")
    
    if not os.path.exists(file_path):
        print(f"Error: File '{file_path}' not found.")
        input("\nPress Enter to continue...")
        return False
    
    result = data_processor.load_data(file_path)
    
    if result:
        print("\nFile loaded successfully!")
        data_info = data_processor.get_data_info()
        print(f"Records: {data_info['rows']:,}")
        print(f"Features: {data_info['columns']}")
        input("\nPress Enter to continue...")
        return True
    else:
        print("\nFailed to load the file. Make sure it's a valid CSV file.")
        input("\nPress Enter to continue...")
        return False

def run_detection(data_processor, model_handler):
    """Run intrusion detection"""
    clear_screen()
    print_header()
    print("RUN INTRUSION DETECTION\n")
    
    if data_processor.data is None:
        print("Error: No data loaded. Please load a CSV file first.")
        input("\nPress Enter to continue...")
        return
    
    print("Processing data...")
    processed_data = data_processor.preprocess_data()
    
    if processed_data is None:
        print("Error: Failed to process data.")
        input("\nPress Enter to continue...")
        return
    
    print("Detecting intrusions...")
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
            
    except Exception as e:
        print(f"Error: {str(e)}")
    
    input("\nPress Enter to continue...")

def view_dataset_info(data_processor):
    """View dataset information"""
    clear_screen()
    print_header()
    print("DATASET INFORMATION\n")
    
    if data_processor.data is None:
        print("Error: No data loaded. Please load a CSV file first.")
        input("\nPress Enter to continue...")
        return
    
    data_info = data_processor.get_data_info()
    file_name = os.path.basename(data_info['file_path'])
    
    print(f"File: {file_name}")
    print(f"Records: {data_info['rows']:,}")
    print(f"Features: {data_info['columns']}")
    
    if data_processor.data is not None:
        print("\nSample Records (first 5):")
        print(data_processor.data.head(5).to_string())
        
        print("\nData Columns:")
        for col in data_processor.data.columns:
            print(f"- {col}")
        
        print("\nColumn Types:")
        if data_processor.numeric_columns:
            print(f"Numeric columns: {len(data_processor.numeric_columns)}")
        if data_processor.categorical_columns:
            print(f"Categorical columns: {len(data_processor.categorical_columns)}")
        if data_processor.label_column:
            print(f"Label column: {data_processor.label_column}")
    
    input("\nPress Enter to continue...")

def show_about():
    """Show about information"""
    clear_screen()
    print_header()
    print("ABOUT\n")
    
    print("AI-Driven Hybrid Approach for Intrusion Detection")
    print("Version 1.0")
    print("\nA system that combines autoencoder and Decision Tree models")
    print("for effective network intrusion detection.")
    print("\nThis application allows users to upload network traffic data")
    print("and perform intrusion detection using a hybrid approach.")
    print("\n© 2023 Intrusion Detection Systems")
    
    input("\nPress Enter to continue...")

def main():
    """Main application function"""
    data_processor = DataProcessor()
    model_handler = ModelHandler()
    
    while True:
        clear_screen()
        print_header()
        print_menu()
        
        try:
            choice = input().strip()
        except EOFError:
            choice = "5"  # Exit if EOF (Ctrl+D) is encountered
        
        if choice == "1":
            load_csv(data_processor)
        elif choice == "2":
            run_detection(data_processor, model_handler)
        elif choice == "3":
            view_dataset_info(data_processor)
        elif choice == "4":
            show_about()
        elif choice == "5":
            clear_screen()
            print("\nThank you for using the AI-Driven Network Intrusion Detection System.")
            print("Goodbye!\n")
            sys.exit(0)
        else:
            print("\nInvalid choice. Please try again.")
            input("\nPress Enter to continue...")

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        clear_screen()
        print("\nApplication terminated by user. Goodbye!\n")
        sys.exit(0)
