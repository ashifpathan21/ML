# train_model.py
import pandas as pd
from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import classification_report, accuracy_score
import joblib

# 1. Load dataset
data = pd.read_csv("feature_vectors_syscallsbinders_frequency_5_Cat.csv")

print("📌 Columns in dataset:", data.columns.tolist())

# Try to detect label column
possible_labels = ["label", "class", "category", "malware", "benign"]
label_col = None
for col in data.columns:
    if col.lower() in possible_labels:
        label_col = col
        break

if label_col is None:
    raise ValueError("❌ No label column found. Please check dataset columns.")

print(f"✅ Using '{label_col}' as target column")

X = data.drop(label_col, axis=1)
y = data[label_col]

# 2. Split data
X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)

# 3. Train model
model = RandomForestClassifier(n_estimators=100, random_state=42)
model.fit(X_train, y_train)

# 4. Evaluate
y_pred = model.predict(X_test)
print("Accuracy:", accuracy_score(y_test, y_pred))
print(classification_report(y_test, y_pred))

# 5. Save model
joblib.dump(model, "saved_model.pkl")
print("✅ Model trained and saved as saved_model.pkl")
