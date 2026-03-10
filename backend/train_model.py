import os
import sys
import pandas as pd
import numpy as np
import tldextract
import math
from urllib.parse import urlparse
import re
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import accuracy_score, precision_score, recall_score, classification_report
import pickle
import concurrent.futures

PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))
if PROJECT_ROOT not in sys.path:
    sys.path.append(PROJECT_ROOT)

from utils.feature_extraction import IP_REGEX, HEX_IP_REGEX, normalize_url

def extract_fast_features(url: str) -> dict:
    try:
        normalized = normalize_url(url)
    except Exception:
        normalized = url
        
    try:
        ext = tldextract.extract(normalized)
    except Exception:
        ext = None

    if ext:
        subdomains = [s for s in ext.subdomain.split('.') if s] if ext.subdomain else []
        if not ext.subdomain:
            feature_url_len = len(normalized) + 4
            feature_dots = normalized.count('.') + 1
            feature_subdomains = 1.0 
        else:
            feature_url_len = len(normalized)
            feature_dots = normalized.count('.')
            feature_subdomains = len(subdomains)
        domain_part = ext.domain
    else:
        feature_url_len = len(normalized)
        feature_dots = normalized.count('.')
        feature_subdomains = 0.0
        domain_part = normalized
        
    features = {
        'url_length': float(feature_url_len),
        'num_dots': float(feature_dots),
        'has_ip': 1.0 if IP_REGEX.match(domain_part) or HEX_IP_REGEX.match(domain_part) else 0.0,
        'has_at_symbol': 1.0 if '@' in normalized else 0.0,
        'num_subdomains': float(feature_subdomains), 
        'is_https': 1.0 if normalized.startswith('https://') else 0.0,
        'url_entropy': float(-sum(p * math.log2(p) for p in (normalized.count(c) / len(normalized) for c in set(normalized)))),
        'num_hyphens': float(normalized.count('-')),
        'path_length': float(len(urlparse(normalized).path)),
        'has_suspicious_tld': 1.0 if ext and ext.suffix and any(ext.suffix.endswith(t) for t in ['xyz', 'top', 'pw', 'tk', 'ml', 'ga', 'cf', 'gq', 'ng', 'buzz', 'info', 'online', 'site']) else 0.0,
    }
    return features

def load_datasets():
    print("Loading datasets...")
    dfs = []
    
    # 1. compromised_url_history.csv (All phishing)
    try:
        df1 = pd.read_csv('../compromised_url_history.csv', header=None, names=['url'], skiprows=2)
        df1['url'] = df1['url'].astype(str).str.strip()
        df1 = df1[df1['url'] != '']
        df1['label'] = 1
        dfs.append(df1[['url', 'label']])
        print(f"Loaded compromised_url_history.csv: {len(df1)} rows")
    except Exception as e:
        print(f"Error loading compromised: {e}")

    # 2. Phishing URLs.csv (url, Type)
    try:
        df2 = pd.read_csv('../Phishing URLs.csv')
        df2 = df2.rename(columns={'Type': 'label'})
        df2['label'] = df2['label'].apply(lambda x: 1 if str(x).lower().strip() == 'phishing' else 0)
        dfs.append(df2[['url', 'label']])
        print(f"Loaded Phishing URLs.csv: {len(df2)} rows")
    except Exception as e:
        print(f"Error loading Phishing URLs: {e}")

    # 3. URL dataset.csv (url, type)
    try:
        df3 = pd.read_csv('../URL dataset.csv')
        df3['label'] = df3['type'].apply(lambda x: 1 if str(x).lower().strip() == 'phishing' else 0)
        dfs.append(df3[['url', 'label']])
        print(f"Loaded URL dataset.csv: {len(df3)} rows")
    except Exception as e:
        print(f"Error loading URL dataset: {e}")

    # 4. dataset_phishing.csv (url, status)
    try:
        df4 = pd.read_csv('../dataset_phishing.csv')
        df4['label'] = df4['status'].apply(lambda x: 1 if str(x).lower().strip() == 'phishing' else 0)
        dfs.append(df4[['url', 'label']])
        print(f"Loaded dataset_phishing.csv: {len(df4)} rows")
    except Exception as e:
        print(f"Error loading dataset_phishing: {e}")

    # Combine and deduplicate
    combined = pd.concat(dfs, ignore_index=True)
    combined = combined.drop_duplicates(subset=['url'])
    print(f"Total unique URLs: {len(combined)}")
    print(f"Label distribution:\n{combined['label'].value_counts()}")
    return combined

def process_batch(urls):
    return [extract_fast_features(url) for url in urls]

if __name__ == "__main__":
    df = load_datasets()
    
    # We will sample to speed up training, while maintaining a large enough dataset for 99.9% precision
    # Let's use 200,000 legitimate and 200,000 phishing URLs to train if available
    phish = df[df['label'] == 1]
    legit = df[df['label'] == 0]
    
    n_samples = min(250000, len(legit), len(phish))
    print(f"Sampling {n_samples} from each class for balanced robust training...")
    df_balanced = pd.concat([
        phish.sample(n=min(len(phish), n_samples), random_state=42),
        legit.sample(n=min(len(legit), n_samples), random_state=42)
    ])
    
    urls = df_balanced['url'].tolist()
    labels = df_balanced['label'].values
    
    print("Extracting features...")
    # Extract features using ProcessPoolExecutor for CPU bound work
    features_list = []
    chunk_size = 10000
    chunks = [urls[i:i + chunk_size] for i in range(0, len(urls), chunk_size)]
    
    with concurrent.futures.ProcessPoolExecutor() as executor:
        for res in executor.map(process_batch, chunks):
            features_list.extend(res)
            
    X = pd.DataFrame(features_list)
    y = labels
    
    print(f"Feature matrix shape: {X.shape}")
    
    X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42, stratify=y)
    
    print("Training RandomForestClassifier for 99.9% precision...")
    # Using extremely high class_weight for 0 (legitimate) to hit 99.9% precision target
    clf = RandomForestClassifier(n_estimators=200, max_depth=40, class_weight={0: 50000, 1: 1}, min_samples_leaf=10, n_jobs=-1, random_state=42)
    clf.fit(X_train, y_train)
    
    y_pred = clf.predict(X_test)
    
    print("Evaluation on Test Set:")
    acc = accuracy_score(y_test, y_pred)
    prec = precision_score(y_test, y_pred)
    rec = recall_score(y_test, y_pred)
    print(f"Accuracy:  {acc:.5f}")
    print(f"Precision: {prec:.5f} (Target > 99.9%)")
    print(f"Recall:    {rec:.5f}")
    print("\nClassification Report:")
    print(classification_report(y_test, y_pred))
    
    # Save the new model and features
    model_dir = os.path.join(PROJECT_ROOT, 'model')
    os.makedirs(model_dir, exist_ok=True)
    
    model_path = os.path.join(model_dir, 'model.pkl')
    features_path = os.path.join(model_dir, 'model_features.pkl')
    
    with open(model_path, 'wb') as f:
        pickle.dump(clf, f)
        
    with open(features_path, 'wb') as f:
        # Save exact column names used during training
        pickle.dump(list(X.columns), f)
        
    print(f"Model saved to {model_path}")
    print(f"Features saved to {features_path}")
