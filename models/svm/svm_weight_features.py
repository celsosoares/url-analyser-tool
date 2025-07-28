import joblib
import matplotlib.pyplot as plt
import pandas as pd
import numpy as np

# Carrega o modelo SVM linear
svm_model = joblib.load("models/svm/svm_model.pkl")

# Carrega os dados (sem 'url' e 'label')
df = pd.read_csv("datasets/result.csv")
X = df.drop(columns=["url", "label"])
feature_names = X.columns

# Obtém os coeficientes das features
if hasattr(svm_model, "coef_"):
    importances = np.abs(svm_model.coef_[0])  # Usa o módulo para ordenação
else:
    raise ValueError("O modelo não possui coeficientes. Use kernel='linear' para isso.")

# Plot
plt.figure(figsize=(10, 6))
plt.barh(feature_names, importances)
plt.xlabel("Importância Relativa (|coef|)")
plt.title("Importância das Features - SVM (Linear Kernel)")
plt.gca().invert_yaxis()
plt.tight_layout()
plt.show()
