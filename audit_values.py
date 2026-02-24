import json
import numpy as np
import asyncio
import sys
from pathlib import Path
from datetime import datetime

# Add project root to path
sys.path.insert(0, str(Path(__file__).resolve().parent))

from app.utils.deep_feature_extractor import extract, FEATURE_COLS

async def audit_values(url):
    print(f"=== 2 & 5. FEATURE VALUE & DRIFT AUDIT for {url} ===")
    
    # 1. Extract runtime features
    feats = await extract(url)
    
    # 2. Load training stats
    stats_path = Path('models/deep_feature_stats.json')
    if not stats_path.exists():
        print("❌ Training stats not found!")
        return
        
    with open(stats_path) as f:
        stats = json.load(f)
        
    print(f"{'Feature':<30} | {'Runtime Value':<15} | {'Train Mean':<12} | {'Status'}")
    print("-" * 75)
    
    drift_count = 0
    for col in FEATURE_COLS:
        val = feats.get(col, -1)
        s = stats.get(col, {})
        mean = s.get('mean', -1)
        std = s.get('std', 0)
        
        status = "OK"
        # Flags if outside mean +/- 3*std (if val is not sentinel)
        if val != -1 and mean != -1 and std > 0:
            if abs(val - mean) > 3 * std:
                status = "🚨 DRIFT"
                drift_count += 1
        
        # Specific check for domain timing (as suspected)
        if "time_domain" in col:
            print(f"{col:<30} | {val:<15.2f} | {mean:<12.2f} | {status}")
        elif status == "🚨 DRIFT":
             print(f"{col:<30} | {val:<15.2f} | {mean:<12.2f} | {status}")

    print(f"\nTotal drifting features: {drift_count}")

if __name__ == "__main__":
    url = "https://www.google.com"
    asyncio.run(audit_values(url))
