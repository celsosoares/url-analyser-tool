import joblib
import matplotlib.pyplot as plt
import pandas as pd

# Carrega o modelo
rf_model = joblib.load("models/random-forest/rf_model.pkl")

# Mesmos dados usados no treino (sem 'url' e 'label')
df = pd.read_csv("datasets/result.csv")
X = df.drop(columns=["url", "label"])

# Importâncias
importances = rf_model.feature_importances_
feature_names = X.columns

# Plot
plt.figure(figsize=(10, 6))
plt.barh(feature_names, importances)
plt.xlabel("Importância")
plt.title("Importância das Features - Random Forest")
plt.gca().invert_yaxis()
plt.tight_layout()
plt.show()
