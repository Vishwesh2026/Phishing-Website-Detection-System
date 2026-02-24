/**
 * popup.js — Phishing Detector Pro v2
 * ─────────────────────────────────────────────────────────────
 * Reads the cached prediction from chrome.storage.local
 * (written by background.js) and renders the result UI.
 *
 * If no cached result exists for the current tab,
 * it triggers a fresh API call inline.
 */

const API_URL = "http://127.0.0.1:8000/api/v1/predict";

// ── Helpers ───────────────────────────────────────────────────────────────────

function getDomain(url) {
    try {
        return new URL(url).hostname;
    } catch {
        return url;
    }
}

function riskToCardClass(riskLevel, label) {
    if (label === 0) return "safe";
    if (riskLevel === "HIGH") return "phishing-high";
    if (riskLevel === "MEDIUM") return "phishing-medium";
    return "phishing-low";
}

function riskToBarClass(label, riskLevel) {
    if (label === 0) return "safe";
    if (riskLevel === "HIGH") return "danger";
    return "warning";
}


// ── Render functions ──────────────────────────────────────────────────────────

function renderResult(data) {
    const content = document.getElementById("content");
    const footer = document.getElementById("footer");

    const isSafe = data.label === 0;
    const confidencePct = Math.round((data.confidence ?? 0) * 100);
    const domain = getDomain(data.url ?? "");
    const cardClass = riskToCardClass(data.risk_level, data.label);
    const barClass = riskToBarClass(data.label, data.risk_level);
    const latency = data.latency_ms != null ? `${data.latency_ms.toFixed(1)} ms` : "—";
    const modelVer = data.model_version ?? "—";

    const verdictIcon = isSafe ? "✅" : (data.risk_level === "HIGH" ? "🚨" : "⚠️");
    const verdictLabel = isSafe ? "SAFE" : `PHISHING — ${data.risk_level} RISK`;
    const verdictSub = isSafe
        ? `${confidencePct}% confidence — No threat detected`
        : `${confidencePct}% phishing probability`;

    content.innerHTML = `
        <div class="result">
            <div class="verdict-card ${cardClass}">
                <div class="verdict-icon">${verdictIcon}</div>
                <div class="verdict-text">
                    <div class="verdict-label">${verdictLabel}</div>
                    <div class="verdict-sub">${verdictSub}</div>
                </div>
            </div>

            <div class="domain-strip">
                <strong>🌐 ${domain}</strong>
                ${data.url?.length > 60 ? data.url.slice(0, 80) + "…" : (data.url ?? "")}
            </div>

            <div class="confidence-section">
                <div class="confidence-label">
                    <span>Confidence Score</span>
                    <span class="confidence-value">${confidencePct}%</span>
                </div>
                <div class="bar-track">
                    <div
                        class="bar-fill ${barClass}"
                        style="width: ${confidencePct}%"
                    ></div>
                </div>
            </div>

            <div class="meta">
                <div class="meta-item">
                    <div class="label">Risk Level</div>
                    <div class="value">${data.risk_level ?? "—"}</div>
                </div>
                <div class="meta-item">
                    <div class="label">Latency</div>
                    <div class="value">${latency}</div>
                </div>
                <div class="meta-item">
                    <div class="label">Model</div>
                    <div class="value">${modelVer}</div>
                </div>
                <div class="meta-item">
                    <div class="label">Checked At</div>
                    <div class="value">${data.checked_at ? new Date(data.checked_at).toLocaleTimeString() : "—"}</div>
                </div>
            </div>
        </div>
    `;

    footer.textContent = `Phishing Detector Pro • ${modelVer}`;
}

function renderError(message) {
    document.getElementById("content").innerHTML = `
        <div class="result">
            <div class="verdict-card error">
                <div class="verdict-icon">🔌</div>
                <div class="verdict-text">
                    <div class="verdict-label">API Unavailable</div>
                    <div class="verdict-sub">${message}</div>
                </div>
            </div>
            <div class="domain-strip">
                <strong>Make sure the API is running:</strong>
                uvicorn app.main:app --reload
            </div>
        </div>
    `;
}

function renderChecking() {
    document.getElementById("content").innerHTML = `
        <div class="result">
            <div class="verdict-card checking">
                <div class="verdict-icon">🔍</div>
                <div class="verdict-text">
                    <div class="verdict-label">Analyzing URL...</div>
                    <div class="verdict-sub">Running ML inference</div>
                </div>
            </div>
        </div>
    `;
}


// ── Main: get active tab, read or fetch result ────────────────────────────────

async function main() {
    let tab;
    try {
        [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
    } catch (err) {
        renderError("Could not access active tab.");
        return;
    }

    if (!tab?.url?.startsWith("http")) {
        document.getElementById("content").innerHTML = `
            <div class="loading">
                <div style="font-size:28px">🛡️</div>
                <span style="font-size:13px; color:#64748b">Open a website to scan it.</span>
            </div>
        `;
        return;
    }

    // Read cached result from background.js
    const storageKey = `tab_${tab.id}`;
    const stored = await chrome.storage.local.get(storageKey);
    const cached = stored[storageKey];

    // If cached AND same URL → render immediately
    if (cached && cached.url === tab.url) {
        if (cached.error) {
            renderError(cached.error);
        } else {
            renderResult(cached);
        }
        return;
    }

    // No cache → fetch inline and render
    renderChecking();

    try {
        const response = await fetch(API_URL, {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ url: tab.url }),
            signal: AbortSignal.timeout(10_000),
        });

        if (!response.ok) {
            const err = await response.json().catch(() => ({}));
            throw new Error(err.detail ?? `HTTP ${response.status}`);
        }

        const data = await response.json();
        const result = {
            url: tab.url,
            prediction: data.prediction,
            label: data.label,
            confidence: data.confidence,
            risk_level: data.risk_level,
            model_version: data.model_version,
            latency_ms: data.latency_ms,
            checked_at: new Date().toISOString(),
            error: null,
        };

        // Cache for background access
        await chrome.storage.local.set({ [storageKey]: result });
        renderResult(result);

    } catch (err) {
        renderError(err.message ?? "Unknown error");
    }
}

document.addEventListener("DOMContentLoaded", main);
