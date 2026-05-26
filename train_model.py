import os
import pandas as pd
from features import extract_features
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
import joblib

# ✅ Load the dataset
dataset_path = "malicious_phish.csv"
if not os.path.exists(dataset_path):
    print("Error: 'malicious_phish.csv' dataset file not found!")
    print("To retrain the model, please download the 'Malicious URLs Dataset' from Kaggle:")
    print("Link: https://www.kaggle.com/datasets/sid321axn/malicious-urls-dataset")
    print("Place the downloaded CSV in the project root directory and run this script again.")
    import sys
    sys.exit(1)

df = pd.read_csv(dataset_path)

# ✅ Convert 'type' column into binary labels: phishing = 1, benign = 0
df['type'] = df['type'].map({'phishing': 1, 'benign': 0})

# ✅ Drop any rows where 'type' could not be mapped (just in case)
df.dropna(subset=['type'], inplace=True)

# ✅ Extract features for each URL using your custom function
X = df['url'].apply(extract_features).tolist()
y = df['type']

# ✅ Split into training and test sets
X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)

# ✅ Train a Random Forest Classifier
model = RandomForestClassifier()
model.fit(X_train, y_train)

# ✅ Create 'model/' directory if it doesn't exist
if not os.path.exists("model"):
    os.makedirs("model")

# ✅ Save the trained model
joblib.dump(model, "model/phishing_model.pkl")

print("✅ Model trained and saved to model/phishing_model.pkl")
