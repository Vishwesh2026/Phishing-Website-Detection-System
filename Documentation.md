# SafeSurf Phishing Detection System — Technical Documentation

> **Version 3.1** | Production-grade, Infrastructure-Aware Phishing Detection

---

## 1️⃣ System Overview

### What problem this solves
Phishing websites steal credentials by mimicking legitimate services. Blocklists expire instantly — attackers register new domains hourly. This system detects phishing *structurally* from URL anatomy and DNS/SSL infrastructure, not from a static list.

### Why infrastructure-awareness matters
Legitimate businesses build stable, multi-year infrastructure:  
— Domains registered for years, with proper MX/NS/SSL records and low DNS TTLs.  
Attackers use disposable, cheap infrastructure:  
— Domains registered hours ago, bare DNS, no SPF, self-signed or absent SSL.

The ML model learns to spot these patterns across 111 quantitative features.

### What happens when a URL is submitted
```
1. Normalize URL (case, trailing slash, fragments)
2. DNS Guard: does the domain actually exist? (NXDOMAIN → immediate block)
3. Extract 111 features (text analysis + async network calls)
4. XGBoost model outputs raw probability
5. IsotonicRegression calibrates to a true confidence score
6. Risk level assigned and JSON response packaged
```

---

## 2️⃣ Full Architecture

```text
  ┌─────────────────┐  ┌────────────────────┐
  │ Chrome Extension│  │ Security Dashboard │  (index.html — Jinja2 + JS)
  └────────┬────────┘  └─────────┬──────────┘
           │  POST /api/v1/analyze│
           └────────────┬─────────┘
                        ▼
           ┌────────────────────────┐
           │   FastAPI Backend      │  app/main.py
           │   CORS + Body Limit    │  MAX_REQUEST_BODY_BYTES = 8KB
           │   Semaphore Guard      │  MAX_CONCURRENT = 10
           └────────────┬───────────┘
                        │
                        ▼  app/routers/predict.py
           ┌────────────────────────┐
           │  1. URL Canonicalization│  url_normalizer.py
           │     lowercase, no frag │
           └────────────┬───────────┘
                        │
                        ▼  app/services/dns_guard.py
           ┌────────────────────────┐
           │  2. DNS Guard          │  DETERMINISTIC LAYER
           │  Resolve A record      │
           │  NXDOMAIN → invalid ✗  │  returns immediately (< 200ms)
           │  Timeout  → continue ✓ │  defers to ML with sentinels
           └────────────┬───────────┘
                        │  (domain exists)
                        ▼  app/utils/deep_feature_extractor.py
           ┌────────────────────────┐
           │  3. Feature Extraction │  CONCURRENT ASYNC
           │  Layer A: 97 Lexical   │  (URL text, no I/O)
           │  Layer B: 14 Infra     │  (DNS + SSL + WHOIS + HTTP)
           │  Missing → -1 sentinel │
           └────────────┬───────────┘
                        │
                        ▼  app/services/model_service.py
           ┌────────────────────────┐
           │  4. ML Inference       │  PROBABILISTIC LAYER
           │  SimpleImputer (-1→med)│
           │  XGBoost (400 trees)   │
           │  IsotonicRegression    │  probability calibration
           └────────────┬───────────┘
                        │
                        ▼
           ┌────────────────────────┐
           │  5. Response Assembly  │  app/schemas/prediction_schema.py
           │  prediction / label    │  "safe"|"phishing"|"invalid"|"unknown"
           │  confidence / risk     │  "HIGH"|"MEDIUM"|"LOW"
           │  infrastructure info   │  InfrastructureFeatures
           │  domain_info (WHOIS)   │  DomainInfo
           └────────────────────────┘
```

---

## 3️⃣ DNS Guard — Deterministic NXDOMAIN Pre-Check

**File:** `app/services/dns_guard.py`

**Purpose:** Stop the ML pipeline from running on domains that physically cannot exist.

**Why this is necessary:**  
The ML model was trained on real domains (both phishing and legitimate). A non-existent domain (NXDOMAIN) produces a feature vector consisting almost entirely of `-1` sentinels. The model was never trained to handle this and might incorrectly classify it as SAFE purely from the URL text.

**Behavior:**

| DNS Resolution Result | Action | Latency |
|---|---|---|
| A record found | Continue to feature extraction | ~50ms |
| NXDOMAIN (domain doesn't exist) | Return `invalid` / HIGH risk immediately | ~150ms |
| NoAnswer (domain exists, no A record) | Return `invalid` / HIGH risk immediately | ~150ms |
| Timeout (network congestion) | Continue to ML (degraded mode) | 2s |
| Other error | Continue to ML (fail open — security preference) | — |

**Response for NXDOMAIN:**
```json
{
  "prediction": "invalid",
  "label": 1,
  "confidence": 1.0,
  "risk_level": "HIGH",
  "reason": "Domain does not resolve (NXDOMAIN)",
  "infrastructure": null,
  "domain_info": null,
  "latency_ms": 148
}
```

**Security rationale:** Failing open on timeouts is deliberate — a slow DNS response should not prevent a legitimate site from being analyzed. Failing closed (blocking on timeout) would allow attackers to exploit DNS delays as an evasion technique.

---

## 4️⃣ URL Canonicalization

**File:** `app/utils/url_normalizer.py`

Applied **before** DNS Guard and feature extraction to ensure consistent input.

| Transformation | Before | After |
|---|---|---|
| Lowercase scheme + host | `HTTPS://Google.COM` | `https://google.com` |
| Remove default ports | `https://site.com:443/` | `https://site.com/` |
| Strip URL fragments | `https://site.com/page#section` | `https://site.com/page` |
| Normalize trailing slash | `https://site.com/` | `https://site.com` |

**Why this matters:** Without normalization, `https://Google.com` and `https://google.com/` would produce different feature vectors and potentially different predictions, making the model brittle to trivial URL variations that attackers could exploit.

---

## 5️⃣ Feature Extraction — 111 Features

**File:** `app/utils/deep_feature_extractor.py`

### Layer A: Lexical Features (97 features, pure text — no I/O)

Computed from the URL string alone in < 1ms. Counted across 5 URL segments:  
`url`, `domain`, `directory`, `file`, `params`

| Feature Group | Examples | Count |
|---|---|---|
| Special character counts | `qty_dot_url`, `qty_hyphen_domain`, `qty_slash_directory` | 85 |
| Length features | `length_url`, `domain_length`, `file_length` | 5 |
| Domain-specific | `qty_vowels_domain`, `domain_in_ip`, `server_client_domain` | 3 |
| URL-level | `qty_tld_url`, `email_in_url`, `url_shortened`, `qty_params` | 4 |

### Layer B: Infrastructure Features (14 features, async network)

Executed concurrently via `asyncio.gather` with a 15-second timeout ceiling.

| Feature | Source | Description |
|---|---|---|
| `qty_ip_resolved` | DNS A | Number of IP addresses the domain resolves to |
| `qty_nameservers` | DNS NS | Number of authoritative nameservers |
| `qty_mx_servers` | DNS MX | Number of mail exchange records |
| `ttl_hostname` | DNS TTL | DNS time-to-live in seconds |
| `domain_spf` | DNS TXT | Whether SPF record exists (anti-spam) |
| `tls_ssl_certificate` | SSL handshake | 1=valid, 0=invalid, -1=error |
| `time_response` | HTTP HEAD | Latency in seconds to reach the server |
| `qty_redirects` | HTTP | Number of HTTP redirects followed |
| `asn_ip` | RDAP | Autonomous System Number of the hosting IP |
| `time_domain_activation` | WHOIS | Days since domain was registered |
| `time_domain_expiration` | WHOIS | Days until domain registration expires |
| `url_google_index` | Sentinel | Always -1 (Google index not checked at runtime) |
| `domain_google_index` | Sentinel | Always -1 (Google index not checked at runtime) |

### Sentinel Policy (-1)

`-1` is used universally when data is unavailable:
- DNS timeout → `qty_ip_resolved = -1`
- WHOIS failure → `time_domain_activation = -1`
- SSL error → `tls_ssl_certificate = -1`

The ML model is trained on datasets containing these sentinels, so it interprets them correctly as "data unavailable." The `SimpleImputer` at inference replaces them with the training-set column median as a secondary safeguard.

---

## 6️⃣ ML Model — XGBoost + Isotonic Calibration

**File:** `models/phishing_deep_v1.pkl`

### What is XGBoost?
An ensemble of 400 decision trees trained sequentially. Each tree learns from the errors of the previous one (gradient boosting). Each tree specializes in different feature combinations — one tree may focus on newly-registered domains, another on missing SSL.

### Calibration (IsotonicRegression)
XGBoost's raw output is a score, not a true probability. `IsotonicRegression` is fitted on a held-out calibration set (prefit approach) to map raw scores to calibrated probabilities. When the model says 90% confidence, this means historically, approximately 90% of URLs with that score were phishing.

**Why prefit over CalibratedClassifierCV(cv=5)?**  
scikit-learn 1.7 introduced `__sklearn_tags__` on estimator classes. XGBoost 2.x has not yet implemented this, causing `CalibratedClassifierCV(cv=N)` to crash. The prefit approach (manual 3-way split + IsotonicRegression) is mathematically equivalent and fully compatible.

### Model Bundle Structure (pickle)
```python
{
    # Either as a DeepModelBundle object (v1) or a plain dict (clean_v1)
    "imputer":       SimpleImputer,       # handles -1 sentinels
    "xgb":           XGBClassifier,       # raw XGBoost
    "iso_regressor": IsotonicRegression,  # calibration mapping
    "feature_cols":  list[str],           # (Optional) canonical column names
}
```

### Risk Level Mapping
```
confidence ≥ 0.85  →  HIGH RISK
confidence ≥ 0.65  →  MEDIUM RISK
confidence < 0.65  →  LOW RISK
prediction = invalid →  HIGH RISK (deterministic, confidence = 1.0)
```

---

## 7️⃣ Scalable Retraining Pipeline (PhiUSIIL 235k URLs)

Three standalone scripts form the training pipeline:

### Phase 1 — `training/generate_training_dataset.py`

**Training mode** — restricts feature extraction to avoid rate limits and instability:

| Feature | Training Mode | Production Mode |
|---|---|---|
| Lexical (97 features) | ✅ Full | ✅ Full |
| DNS A/NS/MX/TXT | ✅ Synchronous (3s timeout) | ✅ Async (15s timeout) |
| SSL certificate | ❌ Sentinel -1 | ✅ Live handshake |
| WHOIS timing | ❌ Sentinel -1 | ✅ RDAP lookup |
| HTTP latency/redirects | ❌ Sentinel -1 | ✅ Live HEAD request |
| ASN lookup | ❌ Sentinel -1 | ✅ RDAP lookup |

**Why this is safe:**  
At production inference, failed checks also return `-1`. The model trains and predicts on the same sentinel distribution, so the decision boundary is consistent.

**Domain-level caching:**  
All 235k URLs share ~50k–60k unique apex domains. The in-memory `_domain_cache` re-uses DNS results for the same domain across all its URLs — reducing DNS queries by ~75%.

**Concurrency:** `ThreadPoolExecutor(max_workers=40)` with batches of 200.

**Output:** `Dataset/generated_training_dataset_clean.csv` + `models/deep_feature_cols_clean.json`

### Phase 2 — `training/train_deep_clean.py`

```
235,795 URLs → 70% train (165,056) / 10% calibration (23,578) / 20% test (47,161)
└── SimpleImputer (sentinel → median) on train+cal+test
└── XGBClassifier(n_estimators=400, max_depth=6, lr=0.05, subsample=0.8)
     └── scale_pos_weight = safe_count / phishing_count
└── IsotonicRegression.fit(cal_raw_proba, y_cal)
└── Evaluate on test set → metrics_clean.json
```

**PhiUSIIL label convention note:**  
PhiUSIIL uses `label=0` for phishing and `label=1` for legitimate — the **opposite** of the standard convention. The dataset generation script correctly inverts this: `0→1 (phishing)`, `1→0 (safe)`.

### Phase 3 — `training/validate_clean_model.py`

Loads `phishing_deep_clean_v1.pkl` and runs the full production extractor on known-safe domains (google.com, wikipedia.org, github.com). Asserts none are predicted as HIGH-confidence phishing.

---

## 8️⃣ Execution Flow — Step by Step (Pin-to-Pin)

**When a user submits `https://secure-paypal-verify.xyz/auth`:**

1. **API receives request** — `POST /api/v1/analyze`  
   Semaphore check: if 10 analyses are already running, the 11th queues.

2. **URL Canonicalization** — `normalize_url()`  
   `https://secure-paypal-verify.xyz/auth` → (already canonical, no change)

3. **DNS Guard** — `domain_exists("secure-paypal-verify.xyz")`  
   If NXDOMAIN: return immediately with `prediction=invalid`.  
   Otherwise: continue.

4. **Feature extraction** — `extract("https://secure-paypal-verify.xyz/auth")`  
   Layer A: strip scheme → `secure-paypal-verify.xyz/auth`  
   Count: `qty_hyphen_domain=2`, `qty_slash_url=1`, `length_url=32`, ...  
   Layer B (concurrent): DNS returns `qty_ip_resolved=1`, SSL fails → `tls_ssl_certificate=0`, WHOIS→ domain registered 3 days ago → `time_domain_activation=3`.

5. **Feature vector** — `to_vector(feats, feature_cols)` → 111 floats in canonical order.  
   Any missing → `-1`.

6. **Imputation** — `imputer.transform(vec)` replaces `-1` with training medians.

7. **XGBoost inference** — 400 trees each vote; gradient boosting aggregates.  
   Raw score: `0.942`

8. **Calibration** — `iso.predict([0.942])` → `0.9859` (calibrated probability)

9. **Risk mapping** — `0.9859 ≥ 0.85` → `risk_level = "HIGH"`

10. **Response** — Pydantic validates and serializes to JSON, including WHOIS `domain_info`.

11. **Frontend** — Jinja2 renders the red verdict card, fills confidence bar, shows WHOIS age, and explains the risk.

---

## 9️⃣ Failure Handling — Graceful Degradation

| Failure | Response |
|---|---|
| DNS timeout for domain existence check | Allow ML pipeline to proceed (`dns_guard` returns `True`) |
| DNS resolution failure during feature extraction | `qty_ip_resolved=-1` (sentinel), extraction continues |
| WHOIS/RDAP lookup failure | `time_domain_activation=-1`, `domain_info.whois_available=false` |
| SSL handshake error | `tls_ssl_certificate=-1`, extraction continues |
| HTTP request timeout | `time_response=-1`, `qty_redirects=-1` |
| All infrastructure fails | Model predicts from lexical features only, `degraded=true` in response |
| ML model raises exception | Returns `prediction=unknown`, `risk_level=UNKNOWN` |

**Design principle:** The system never crashes on network errors. Every failure is caught, logged, and converted to a sentinel value. The ML model was trained with sentinels in the data, so it degrades gracefully rather than failing spectacularly.

---

## 🔟 Performance Characteristics

| Operation | Expected Latency |
|---|---|
| DNS Guard check (domain exists) | 50–200ms |
| DNS Guard — NXDOMAIN early return | 50–200ms (no further processing) |
| Lexical feature extraction | < 1ms |
| DNS infrastructure features | 100–500ms |
| SSL handshake | 200ms–4s |
| WHOIS/RDAP lookup | 500ms–3s |
| HTTP latency check | 100ms–5s |
| Full analysis (all infra available) | 1.5–5s |
| Full analysis (all infra times out) | exactly 15s (timeout wall) |
| Infra cache hit (same domain, < 5 min) | < 5ms |

**Infrastructure caching:** Results are cached per domain for 5 minutes (`_infra_cache`). Repeated analyses of the same domain within that window return instantly.

---

## 1️⃣1️⃣ Security Architecture

### Why DNS before ML
If we ran the ML model on NXDOMAIN URLs, the feature vector would be `[-1, -1, -1, ...]` from all infrastructure failures + whatever lexical features the URL text has. The model might classify this as SAFE (the URL text might not look suspicious). The DNS Guard prevents this impossible state from reaching the model.

### Sentinel vs. imputation
`-1` sentinels are not removed before training. The model sees `-1` values in both training AND inference whenever infrastructure is unavailable. Imputation to median is a secondary safety net only — not a primary strategy.

### Why feature parity is critical
Training with `time_domain_activation=3` (days) but inferring with seconds would create a massive distribution shift: the model would predict incorrectly on all domains. Every feature in `FEATURE_COLS` has a documented unit and generation rule that is identical between training and inference.

### What this system cannot detect
- **Compromised legitimate domains:** A 10-year-old legitimate WordPress blog that was hacked today will have pristine WHOIS/DNS and pass every check. Only content-based analysis (headless browser rendering) can detect this.
- **Fast-flux phishing with valid infrastructure:** If an attacker buys a clean domain months in advance and properly configures WHOIS/SSL, the infrastructure signals will look legitimate. The lexical features are the primary defense in this case.
- **Visual similarity attacks:** `paypa1.com` (letter O replaced with 1) may have legitimate DNS/SSL. Homoglyph detection is not implemented in v3.1.

---

## 1️⃣2️⃣ Limitations & Future Roadmap

**Not implemented in v3.1:**
- Entropy scoring (Shannon entropy of domain randomness)
- Homoglyph / IDN Punycode detection (`аррlе.com` looks like `apple.com`)
- Keyword lexicon scanning (`login`, `verify`, `secure`, `banking`)
- Content-based scanning (HTML DOM analysis, password input detection)
- Distributed Redis cache for WHOIS/DNS results

**Implemented and operational in v3.1:**
- ✅ DNS Guard (NXDOMAIN pre-check)
- ✅ URL Canonicalization
- ✅ 97 lexical + 14 infrastructure features
- ✅ IsotonicRegression probability calibration
- ✅ 5-minute domain-level infrastructure caching
- ✅ Degraded mode (lexical-only prediction when infra fails)
- ✅ Three-phase 200k-URL retraining pipeline
- ✅ WHOIS domain intelligence in API response and dashboard
- ✅ Chrome Extension with badge alerts
- ✅ Security dashboard with confidence visualization
- ✅ Docker-ready deployment
