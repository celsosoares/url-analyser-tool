import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report
import joblib
import os

# Load dataset
df = pd.read_csv("/home/celso/git/url-analyser-tool/data/phishing.csv")

label_mapping = {
    -1: 0,   # legítimo
    1: 2     # phishing
}
df['class'] = df['class'].map(label_mapping)

# Separate features and labels
X = df.drop('class', axis=1)
y = df['class']

# Split the data
X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)

# Creates and trains the model
model = RandomForestClassifier(n_estimators=100, random_state=42)
model.fit(X_train, y_train)

# Evaluate the model
y_pred = model.predict(X_test)
print(classification_report(y_test, y_pred))

# Save the model
MODEL_PATH = os.path.join("model", "rf_model.pkl")
joblib.dump(model, MODEL_PATH)
print(f"Modelo salvo em: {MODEL_PATH}")
