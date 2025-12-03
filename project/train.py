import pandas as pd
import numpy as np
import os, json, joblib
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import StandardScaler
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import accuracy_score

# -----------------------------
# 1. Dataset Loading
# -----------------------------
DATA_PATH = os.path.join('data', 'data.csv')
print(f"Loading dataset: {DATA_PATH}")

df = pd.read_csv(DATA_PATH, low_memory=False)
print("Shape:", df.shape)

# -----------------------------
# 2. Detect label column
# -----------------------------
label_candidates = [c for c in df.columns if any(k in c.lower() for k in ('label', 'class', 'target', 'phish', 'malicious', 'status'))]
if not label_candidates:
    raise ValueError("❌ No label column found. Please rename your target column to something like 'phish' or 'label'.")

label_col = label_candidates[0]
print(f"Detected label column: {label_col}")

# -----------------------------
# 3. Clean Data
# -----------------------------
df = df.dropna(subset=[label_col])
df = df.sample(frac=1, random_state=42).reset_index(drop=True)

# Convert categorical labels (if any)
if df[label_col].dtype == 'O':  # string labels
    df[label_col] = df[label_col].astype(str).str.lower().map({
        'phishing': 1, 'phish': 1, 'bad': 1, 'malicious': 1,
        'legit': 0, 'legitimate': 0, 'good': 0, 'benign': 0
    }).fillna(0)

# Keep only numeric columns
num_df = df.select_dtypes(include=[np.number]).copy()
if label_col not in num_df.columns:
    num_df[label_col] = df[label_col].astype(float)

# Drop duplicates or constant columns
num_df = num_df.loc[:, num_df.apply(pd.Series.nunique) > 1]

# -----------------------------
# 4. Split Features & Labels
# -----------------------------
X = num_df.drop(columns=[label_col])
y = num_df[label_col].astype(int)

print("Features shape:", X.shape)
print("Labels distribution:\n", y.value_counts())

X_train, X_test, y_train, y_test = train_test_split(
    X, y, test_size=0.2, random_state=42, stratify=y
)

# -----------------------------
# 5. Scale and Train Model
# -----------------------------
scaler = StandardScaler()
X_train_s = scaler.fit_transform(X_train)
X_test_s = scaler.transform(X_test)

model = RandomForestClassifier(
    n_estimators=200,
    max_depth=None,
    random_state=42,
    class_weight='balanced'
)
model.fit(X_train_s, y_train)

# -----------------------------
# 6. Evaluate
# -----------------------------
y_pred = model.predict(X_test_s)
acc = accuracy_score(y_test, y_pred)
print(f"\n✅ Model trained successfully! Test Accuracy: {acc * 100:.2f}%")

# -----------------------------
# 7. Save Models
# -----------------------------
os.makedirs('models', exist_ok=True)
joblib.dump(model, os.path.join('models', 'rf_model.joblib'))
joblib.dump(scaler, os.path.join('models', 'scaler.joblib'))

# Save metadata
meta = {
    'accuracy': round(acc * 100, 2),
    'n_features': X.shape[1],
    'n_samples': len(df),
    'label_col': label_col,
}
with open(os.path.join('models', 'metadata.json'), 'w', encoding='utf-8') as f:
    json.dump(meta, f, indent=2)

print("\n✅ Model, Scaler, and Metadata saved in /models/")
print("➡️  Ready to run your app:  python app.py")
