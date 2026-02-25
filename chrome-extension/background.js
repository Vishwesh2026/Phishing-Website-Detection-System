// ─────────────────────────────────────────────────────────────
// background.js — SafeSurf Extension v3.1
// ─────────────────────────────────────────────────────────────
// Calls the production-grade /api/v1/predict endpoint.
// Stores result in chrome.storage.local for the popup to read.
// Shows badge + notification on phishing detection.
// ─────────────────────────────────────────────────────────────

const API_URL = "http://127.0.0.1:8000/api/v1/analyze";

// Track last checked URL per tab to avoid duplicate API calls
const lastCheckedPerTab = new Map();
const debounceTimers = new Map();

// ── Tab lifecycle listeners ───────────────────────────────────────────────────

chrome.tabs.onUpdated.addListener((tabId, changeInfo, tab) => {
    if (changeInfo.status === "complete" && tab.url) {
        debounceCheck(tabId, tab.url);
    }
});

chrome.tabs.onRemoved.addListener((tabId) => {
    lastCheckedPerTab.delete(tabId);
    debounceTimers.delete(tabId);
    chrome.storage.local.remove(`tab_${tabId}`);
});

// ── Debounce (avoid duplicate checks on rapid navigation) ─────────────────────

function debounceCheck(tabId, url) {
    if (debounceTimers.has(tabId)) {
        clearTimeout(debounceTimers.get(tabId));
    }
    const timer = setTimeout(() => checkUrl(tabId, url), 600);
    debounceTimers.set(tabId, timer);
}

// ── Core prediction logic ─────────────────────────────────────────────────────

async function checkUrl(tabId, url) {
    if (!url.startsWith("http")) return;
    if (lastCheckedPerTab.get(tabId) === url) return;
    lastCheckedPerTab.set(tabId, url);

    // Set "checking" badge
    chrome.action.setBadgeText({ tabId, text: "..." });
    chrome.action.setBadgeBackgroundColor({ tabId, color: "#6366f1" });

    let result = null;

    try {
        const response = await fetch(API_URL, {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ url }),
            signal: AbortSignal.timeout(20000),   // 20s timeout (infra extraction ≤15s)
        });

        if (!response.ok) {
            throw new Error(`API responded with status ${response.status}`);
        }

        const data = await response.json();

        // Validate expected response shape
        if (typeof data.label !== "number" || typeof data.confidence !== "number") {
            throw new Error("Unexpected API response shape");
        }

        result = {
            url,
            prediction: data.prediction,
            label: data.label,
            confidence: data.confidence,
            risk_level: data.risk_level,
            model_version: data.model_version,
            latency_ms: data.latency_ms,
            domain_info: data.domain_info ?? null,
            degraded: data.degraded ?? false,
            checked_at: new Date().toISOString(),
            error: null,
        };

        // ── Update badge ─────────────────────────────────────────────────────
        const confidencePct = Math.round(data.confidence * 100);

        if (data.label === 1) {
            // Phishing
            const badgeColor = data.risk_level === "HIGH" ? "#dc2626"
                : data.risk_level === "MEDIUM" ? "#f97316"
                    : "#eab308";
            chrome.action.setBadgeText({ tabId, text: "⚠" });
            chrome.action.setBadgeBackgroundColor({ tabId, color: badgeColor });

            // Notification only for HIGH/MEDIUM risk
            if (data.risk_level !== "LOW") {
                chrome.notifications.create({
                    type: "basic",
                    iconUrl: "https://cdn-icons-png.flaticon.com/512/564/564619.png",
                    title: `⚠️ Phishing Alert — ${data.risk_level} Risk`,
                    message: `Confidence: ${confidencePct}% phishing probability detected on this page.`,
                    priority: 2,
                });
            }
        } else {
            // Safe
            chrome.action.setBadgeText({ tabId, text: "✓" });
            chrome.action.setBadgeBackgroundColor({ tabId, color: "#16a34a" });
        }

    } catch (err) {
        console.warn("Phishing check failed:", err.message);
        chrome.action.setBadgeText({ tabId, text: "?" });
        chrome.action.setBadgeBackgroundColor({ tabId, color: "#9ca3af" });
        result = {
            url,
            prediction: null,
            label: null,
            confidence: null,
            risk_level: null,
            model_version: null,
            latency_ms: null,
            checked_at: new Date().toISOString(),
            error: err.message,
        };
    }

    // Persist result for popup
    chrome.storage.local.set({ [`tab_${tabId}`]: result });
}
