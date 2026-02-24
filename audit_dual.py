import asyncio
import sys
from pathlib import Path

# Add project root to path
sys.path.insert(0, str(Path(__file__).resolve().parent))

from app.services.model_service import ModelService

async def audit_dual(url):
    print(f"=== 8. QUICK VS DEEP COMPARISON for {url} ===")
    
    svc = ModelService()
    svc.load()
    
    # 1. Quick Scan
    quick = svc.predict_quick(url)
    print(f"Quick Scan: result={quick['prediction']}, confidence={quick['confidence']:.4f}")
    
    # 2. Deep Scan
    from app.utils.deep_feature_extractor import extract
    feats = await extract(url)
    deep = svc.predict_deep(feats)
    print(f"Deep Scan:  result={deep['prediction']}, confidence={deep['confidence']:.4f}")
    
    if quick['label'] != deep['label']:
        print("🚨 DISAGREEMENT DETECTED!")
    else:
        print("✓ Models agree.")

if __name__ == "__main__":
    url = "https://www.google.com"
    asyncio.run(audit_dual(url))
