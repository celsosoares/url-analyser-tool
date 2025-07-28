from xgboost import plot_importance
import joblib
import matplotlib.pyplot as plt

# Carrega modelo
xgb_model = joblib.load("models/xgboost/xgb_model.pkl")

# Plota
plt.figure(figsize=(10, 6))
plot_importance(xgb_model, max_num_features=20, importance_type='gain')
plt.title("Importância das Features - XGBoost")
plt.tight_layout()
plt.show()
