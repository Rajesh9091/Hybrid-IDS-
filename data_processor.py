"""
Data processor for handling CSV data
"""
import pandas as pd
import numpy as np
from sklearn.preprocessing import StandardScaler

class DataProcessor:
    def __init__(self):
        """Initialize the data processor"""
        self.data = None
        self.preprocessed_data = None
        self.data_info = None
        self.scaler = StandardScaler()
        
        # Define columns that are typically in network intrusion datasets
        # These are common columns in NSL-KDD and CICIDS datasets
        self.numeric_columns = None
        self.categorical_columns = None
        self.label_column = None
    
    def load_data(self, file_path):
        """
        Load CSV data from the specified file path
        
        Args:
            file_path: Path to the CSV file
            
        Returns:
            Boolean indicating success or failure
        """
        try:
            # Load the CSV file
            self.data = pd.read_csv(file_path)
            
            # Basic data validation
            if self.data.empty or len(self.data.columns) < 5:  # Arbitrary minimum columns
                print("Data is empty or has too few columns")
                return False
            
            # Identify column types
            self._identify_column_types()
            
            # Store data information
            self.data_info = {
                'rows': len(self.data),
                'columns': len(self.data.columns),
                'file_path': file_path
            }
            
            return True
            
        except Exception as e:
            print(f"Error loading data: {str(e)}")
            return False
    
    def _identify_column_types(self):
        """Identify numeric, categorical, and label columns in the dataset"""
        # Common label columns in intrusion datasets
        possible_label_columns = [
            'label', 'class', 'attack', 'attack_type', 'attack_cat', 
            'Label', 'Class', 'Attack', 'Attack_Type', 'Attack_Cat'
        ]
        
        # Try to find the label column
        for col in possible_label_columns:
            if col in self.data.columns:
                self.label_column = col
                break
        
        # If label column not found, assume the last column is the label
        if self.label_column is None and len(self.data.columns) > 0:
            self.label_column = self.data.columns[-1]
        
        # Identify numeric and categorical columns
        self.numeric_columns = []
        self.categorical_columns = []
        
        for col in self.data.columns:
            if col == self.label_column:
                continue
                
            if self.data[col].dtype in ['int64', 'float64']:
                self.numeric_columns.append(col)
            else:
                self.categorical_columns.append(col)
    
    def preprocess_data(self):
        """
        Preprocess the loaded data for model input
        
        Returns:
            Dictionary containing preprocessed features and labels
        """
        if self.data is None:
            print("No data loaded")
            return None
        
        try:
            # Make a copy of the data
            df = self.data.copy()
            
            # Handle missing values
            df = self._handle_missing_values(df)
            
            # Handle categorical features
            df = self._encode_categorical_features(df)
            
            # Normalize numeric features
            df = self._normalize_numeric_features(df)
            
            # Extract features and labels
            X = df.drop(columns=[self.label_column], errors='ignore').values
            
            result = {'features': X}
            
            # Add labels if available
            if self.label_column in df.columns:
                y = df[self.label_column].values
                result['labels'] = y
            
            self.preprocessed_data = result
            return result
            
        except Exception as e:
            print(f"Error preprocessing data: {str(e)}")
            return None
    
    def _handle_missing_values(self, df):
        """Handle missing values in the dataset"""
        # Fill numeric columns with mean
        for col in self.numeric_columns:
            if col in df.columns and df[col].isnull().any():
                df[col] = df[col].fillna(df[col].mean())
        
        # Fill categorical columns with mode
        for col in self.categorical_columns:
            if col in df.columns and df[col].isnull().any():
                df[col] = df[col].fillna(df[col].mode()[0])
        
        return df
    
    def _encode_categorical_features(self, df):
        """Encode categorical features using one-hot encoding"""
        if not self.categorical_columns:
            return df
            
        # One-hot encode categorical columns
        df_encoded = pd.get_dummies(
            df, 
            columns=self.categorical_columns,
            drop_first=True,
            dummy_na=False
        )
        
        return df_encoded
    
    def _normalize_numeric_features(self, df):
        """Normalize numeric features"""
        if not self.numeric_columns:
            return df
            
        # Get only numeric columns that exist in the dataframe
        valid_numeric_cols = [col for col in self.numeric_columns if col in df.columns]
        
        if valid_numeric_cols:
            # Fit and transform
            df[valid_numeric_cols] = self.scaler.fit_transform(df[valid_numeric_cols])
        
        return df
    
    def get_data_info(self):
        """Get information about the loaded data"""
        return self.data_info
