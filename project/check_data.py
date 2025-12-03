import pandas as pd

p = 'data/data.csv'  # path to your dataset
print("Loading:", p)
df = pd.read_csv(p, low_memory=False)

print("Shape:", df.shape)
print("\nColumns (first 40):")
for i, c in enumerate(df.columns[:40], 1):
    print(f"{i:02d}. {c}")

print("\nLast 10 columns:")
for c in df.columns[-10:]:
    print(" -", c)

label_candidates = [c for c in df.columns if any(k in c.lower() for k in ('label','class','target','is_phish','phish','malicious','result'))]
print("\nLikely label columns:", label_candidates)

if label_candidates:
    lab = label_candidates[0]
    print(f"\nValue counts for label column '{lab}':")
    print(df[lab].value_counts(dropna=False).head(20))
else:
    print("\nNo obvious label column found. Showing unique values for last 3 columns to inspect:")
    for c in df.columns[-3:]:
        vals = df[c].dropna().astype(str).unique()[:20]
        print(f"Column {c}: sample unique values -> {vals}")
