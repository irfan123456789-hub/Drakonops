---
title: "project"
weight: 3
---
Perfect — you’ve shared logs from a **PowerShell-based attack simulation**, likely involving **encoded command execution, web client downloads, and obfuscated scripts** — classic indicators of malicious PowerShell activity (e.g., Cobalt Strike, Empire, or custom malware).

Since you’ve already loaded the data and confirmed the structure, let’s **refine the feature engineering and Isolation Forest training** specifically for this dataset.

&nbsp;

```
import pandas as pd
import json

# Load and normalize
data = []
with open("dcsync.json", "r") as f:
    for line in f:
        try:
            data.append(json.loads(line))
        except:
            continue

df = pd.json_normalize(data)
print(f"✅ Loaded {len(df)} events.")
```

&nbsp;

&nbsp;

![profile](/resources/qwen_icon_dark_84-2.png)

Qwen3-Max-Preview7:00 pm

Perfect — you’ve shared logs from a **PowerShell-based attack simulation**, likely involving **encoded command execution, web client downloads, and obfuscated scripts** — classic indicators of malicious PowerShell activity (e.g., Cobalt Strike, Empire, or custom malware).

Since you’ve already loaded the data and confirmed the structure, let’s **refine the feature engineering and Isolation Forest training** specifically for this dataset.

* * *

## ✅ STEP 1: Normalize & Load the Data (Again, for Clarity)

```python
import pandas as pd
import json

# Load and normalize
data = []
with open("dcsync.json", "r") as f:
    for line in f:
        try:
            data.append(json.loads(line))
        except:
            continue

df = pd.json_normalize(data)
print(f"✅ Loaded {len(df)} events.")
```

* * *

## ✅ STEP 2: Focus on High-Risk Channels

Your logs show events from:

- `Windows PowerShell`
- `Microsoft-Windows-PowerShell/Operational`
- `Microsoft-Windows-Sysmon/Operational`
- `security`

```
high_risk_channels = [
    'Windows PowerShell',
    'Microsoft-Windows-PowerShell/Operational',
    'Microsoft-Windows-Sysmon/Operational'
]

df = df[df['Channel'].isin(high_risk_channels)].copy()
print(f"✅ Filtered to {len(df)} high-risk events.")
```

&nbsp;

## STEP 3: Feature Engineering — Tailored for PowerShell Attacks

We’ll extract features that flag **suspicious PowerShell behavior**:

### 🎯 Key Features to Create:

![67d53cba0e6f8cd73cc3374211afc696.png](/resources/67d53cba0e6f8cd73cc3374211afc696.png)

&nbsp;

&nbsp;

```python
import numpy as np
from sklearn.preprocessing import LabelEncoder

# Convert timestamp
df['@timestamp'] = pd.to_datetime(df['@timestamp'], errors='coerce')
df['Hour'] = df['@timestamp'].dt.hour
df['DayOfWeek'] = df['@timestamp'].dt.dayofweek

# Encode categorical features
categorical_features = ['EventID', 'Channel', 'AccountName', 'Hostname']
for col in categorical_features:
    if col in df.columns:
        le = LabelEncoder()
        df[col + '_Encoded'] = le.fit_transform(df[col].astype(str).fillna('Unknown'))

# Feature: CommandLine length
def get_command_text(row):
    # Try Payload first, then Message, then ContextInfo
    for col in ['Payload', 'Message', 'ContextInfo']:
        if col in row and isinstance(row[col], str):
            return row[col]
    return ""

df['CommandText'] = df.apply(get_command_text, axis=1)
df['CommandLineLength'] = df['CommandText'].str.len().fillna(0)

# Feature: Base64 detection
def has_base64(text):
    if not isinstance(text, str):
        return 0
    # Look for PowerShell base64 flags or long base64-like strings
    if any(flag in text for flag in ['-enc ', '-e ', ' -enc', ' -e']):
        return 1
    # Heuristic: long string with no spaces and A-Za-z0-9+/= chars
    if len(text) > 200 and ' ' not in text[:100] and all(c in 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=' for c in text[:200]):
        return 1
    return 0

df['HasBase64'] = df['CommandText'].apply(has_base64)

# Feature: WebClient detection
def has_webclient(text):
    if not isinstance(text, str):
        return 0
    patterns = [
        'System.Net.WebClient',
        'DownloadString',
        'DownloadData',
        'DownloadFile',
        'Net.WebClient',
        'new-object net.webclient'
    ]
    return int(any(p.lower() in text.lower() for p in patterns))

df['HasWebClient'] = df['CommandText'].apply(has_webclient)

# Feature: RC4 detection (common in implants)
def has_rc4(text):
    if not isinstance(text, str):
        return 0
    patterns = [
        'RC4',
        '$S[$_], $S[$J] = $S[$J], $S[$_]',
        '256 | ForEach-Object',
        'XOR $S',
        'Key Scheduling Algorithm'
    ]
    return int(any(p.lower() in text.lower() for p in patterns))

df['HasRC4'] = df['CommandText'].apply(has_rc4)

# Feature: User event frequency
if 'AccountName' in df.columns:
    user_freq = df['AccountName'].value_counts()
    df['UserEventCount'] = df['AccountName'].map(user_freq).fillna(0)

# Label for evaluation (NOT used in training)
SUSPICIOUS_PATTERNS = [
    'System.Net.WebClient',
    'DownloadString',
    'RC4',
    '-enc ',
    'Get-Random',
    'ForEach-Object',
    'New-Object',
    'Out-Null'  # Often abused to hide output
]

df['IsSuspiciousEvent'] = df['CommandText'].apply(
    lambda x: 1 if isinstance(x, str) and any(p.lower() in x.lower() for p in SUSPICIOUS_PATTERNS) else 0
)

print("✅ Feature engineering complete!")
```

&nbsp;

&nbsp;

## ✅ STEP 4: Prepare Feature Matrix

```python
feature_columns = [
    'EventID_Encoded',
    'Channel_Encoded',
    'AccountName_Encoded',
    'Hostname_Encoded',
    'Hour',
    'DayOfWeek',
    'CommandLineLength',
    'HasBase64',
    'HasWebClient',
    'HasRC4',
    'UserEventCount'
]

# Only keep columns that exist and are numeric
feature_columns = [col for col in feature_columns if col in df.columns]
X = df[feature_columns].fillna(0)  # Fill NaN with 0

print("✅ Selected features:", feature_columns)
print("✅ Feature matrix shape:", X.shape)




✅ STEP 5: Train Isolation Forest
python



from sklearn.ensemble import IsolationForest

iso_forest = IsolationForest(
    n_estimators=100,
    contamination=0.05,  # Assume 5% anomalies
    random_state=42,
    n_jobs=-1
)

iso_forest.fit(X)

df['Anomaly'] = iso_forest.predict(X)  # -1 = anomaly, 1 = normal
df['AnomalyScore'] = iso_forest.decision_function(X)  # Lower = more anomalous

print("✅ Model trained!")
print("Anomaly distribution:")
print(df['Anomaly'].value_counts())
✅ STEP 6: Evaluate Performance
python



# Calculate Recall and FPR using IsSuspiciousEvent as ground truth
suspicious = df[df['IsSuspiciousEvent'] == 1]
anomalous_suspicious = suspicious[suspicious['Anomaly'] == -1]

print(f"Total Suspicious Events: {len(suspicious)}")
print(f"Detected as Anomaly: {len(anomalous_suspicious)}")

if len(suspicious) > 0:
    recall = len(anomalous_suspicious) / len(suspicious)
    print(f"🎯 Recall: {recall:.2%}")

non_suspicious = df[df['IsSuspiciousEvent'] == 0]
fp = non_suspicious[non_suspicious['Anomaly'] == -1]
fpr = len(fp) / len(non_suspicious) if len(non_suspicious) > 0 else 0
print(f"🎯 False Positive Rate: {fpr:.2%}")
🎯 Your goal: Recall ≥85%, FPR <5% 





✅ STEP 7: Visualize & Interpret Results
python



import matplotlib.pyplot as plt
import seaborn as sns

# Plot anomaly scores
plt.figure(figsize=(12, 5))

plt.subplot(1, 2, 1)
sns.histplot(data=df, x='AnomalyScore', hue='IsSuspiciousEvent', kde=True)
plt.title('Anomaly Score: Suspicious vs Normal Events')

plt.subplot(1, 2, 2)
top_anomalies = df.nsmallest(10, 'AnomalyScore')
sns.barplot(data=top_anomalies, y='EventID', x='AnomalyScore', orient='h')
plt.title('Top 10 Most Anomalous Events by EventID')

plt.tight_layout()
plt.show()

# Show top 5 most anomalous events
print("\n🔍 Top 5 Most Anomalous Events:")
display_cols = ['@timestamp', 'EventID', 'Channel', 'AccountName', 'AnomalyScore', 'HasBase64', 'HasWebClient', 'HasRC4']
print(df.nsmallest(5, 'AnomalyScore')[display_cols].to_string())




✅ STEP 8: Hyperparameter Tuning (Your Responsibility 😊)
python



from sklearn.model_selection import ParameterGrid

param_grid = {
    'contamination': [0.01, 0.03, 0.05, 0.1],
    'n_estimators': [50, 100, 200]
}

best_recall = 0
best_params = None

for params in ParameterGrid(param_grid):
    model = IsolationForest(**params, random_state=42, n_jobs=-1)
    model.fit(X)
    preds = model.predict(X)
    df['Anomaly'] = preds

    suspicious = df[df['IsSuspiciousEvent'] == 1]
    detected = suspicious[suspicious['Anomaly'] == -1]
    recall = len(detected) / len(suspicious) if len(suspicious) > 0 else 0

    if recall > best_recall:
        best_recall = recall
        best_params = params

print("✅ Best Parameters:", best_params)
```

&nbsp;

&nbsp;

&nbsp;
