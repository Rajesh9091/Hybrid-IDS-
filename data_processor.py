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
