import json
import pandas as pd
import sys
from pathlib import Path

# Add project root to path
sys.path.insert(0, str(Path(__file__).resolve().parent))

from app.utils.deep_feature_extractor import FEATURE_COLS

def audit_feature_order():
    print("=== 1. FEATURE ORDER VALIDATION ===")
    
    # Load training columns from dataset
    df = pd.read_csv('Dataset/dataset_full.csv', nrows=1)
    train_cols = [c for c in df.columns if c != 'phishing']
    
    # Load saved cols if exist
    saved_cols_path = Path('models/deep_feature_cols.json')
    if saved_cols_path.exists():
        with open(saved_cols_path) as f:
            saved_cols = json.load(f)
    else:
        saved_cols = []
    
    runtime_cols = FEATURE_COLS
    
    print(f"Number of features:")
    print(f"  Dataset: {len(train_cols)}")
    print(f"  Saved:   {len(saved_cols)}")
    print(f"  Runtime: {len(runtime_cols)}")
    
    # Check mismatches
    mismatches = []
    max_len = max(len(train_cols), len(runtime_cols))
    
    for i in range(max_len):
        t = train_cols[i] if i < len(train_cols) else "MISSING"
        r = runtime_cols[i] if i < len(runtime_cols) else "MISSING"
        if t != r:
            mismatches.append((i, t, r))
            
    if not mismatches:
        print("✓ Feature order matches exactly!")
    else:
        print(f"❌ Found {len(mismatches)} mismatches!")
        print("First 5 mismatches:")
        for i, t, r in mismatches[:5]:
            print(f"  Index {i:3d}: Train='{t}' vs Runtime='{r}'")
            
    print("\nFirst 10 features comparison:")
    print(f"{'Index':<6} | {'Training (Dataset)':<25} | {'Runtime (Extractor)':<25}")
    print("-" * 65)
    for i in range(10):
        t = train_cols[i] if i < len(train_cols) else "N/A"
        r = runtime_cols[i] if i < len(runtime_cols) else "N/A"
        print(f"{i:<6} | {t:<25} | {r:<25}")

if __name__ == "__main__":
    audit_feature_order()
