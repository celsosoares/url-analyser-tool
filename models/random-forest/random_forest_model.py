import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report
import joblib
import os
from sklearn.metrics import confusion_matrix
import seaborn as sns
import matplotlib.pyplot as plt

# Carrega o dataset
df = pd.read_csv("/home/celso/git/url-analyser-tool/datasets/result.csv")

# Remove a coluna de URL (não é usada como feature direta)
X = df.drop(columns=["label", "url"])
y = df["label"]

# Divide os dados em treino e teste
X_train, X_test, y_train, y_test = train_test_split(
    X, y, test_size=0.2, random_state=42
)

# Cria e treina o modelo
model = RandomForestClassifier(n_estimators=100, random_state=42)
model.fit(X_train, y_train)

# Avalia o modelo
y_pred = model.predict(X_test)
print(classification_report(y_test, y_pred))

# Matriz de Confusão
cm = confusion_matrix(y_test, y_pred)
sns.heatmap(cm, annot=True, fmt="d", cmap="Blues")
plt.xlabel("Predito")
plt.ylabel("Real")
plt.title("Matriz de Confusão do Random Forest")
plt.show()

# Salva o modelo treinado
os.makedirs("model", exist_ok=True)
MODEL_PATH = os.path.join("models", "random-forest/rf_model.pkl")
joblib.dump(model, MODEL_PATH)
print(f"Modelo salvo em: {MODEL_PATH}")
