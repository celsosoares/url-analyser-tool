import pandas as pd
from xgboost import XGBClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report
import joblib
import os
from sklearn.metrics import confusion_matrix
import seaborn as sns
import matplotlib.pyplot as plt


# Carrega o dataset
df = pd.read_csv("/home/celso/git/url-analyser-tool/datasets/result.csv")

# Prepara dados: remove colunas que não são usadas como feature
X = df.drop(columns=["label", "url"])
y = df["label"]

# Divide em treino e teste
X_train, X_test, y_train, y_test = train_test_split(
    X, y, test_size=0.2, random_state=42
)

# Cria e treina o modelo com XGBoost
model = XGBClassifier(
    n_estimators=100,
    max_depth=4,
    learning_rate=0.1,
    eval_metric="logloss",
    random_state=42
)
model.fit(X_train, y_train)

# Avaliação do modelo
y_pred = model.predict(X_test)
print(classification_report(y_test, y_pred))

# Matriz de Confusão
cm = confusion_matrix(y_test, y_pred)
sns.heatmap(cm, annot=True, fmt="d", cmap="Blues")
plt.xlabel("Predito")
plt.ylabel("Real")
plt.title("Matriz de Confusão do XGBoost")
plt.show()

# Salva o modelo
os.makedirs("model", exist_ok=True)
MODEL_PATH = os.path.join("models", "xgboost/xgb_model.pkl")
joblib.dump(model, MODEL_PATH)
print(f"Modelo XGBoost salvo em: {MODEL_PATH}")
