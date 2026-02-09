// -------------------- STATE --------------------

// Track last checked URL per tab
const lastCheckedPerTab = new Map();

// Debounce timers per tab
const debounceTimers = new Map();

// -------------------- TAB EVENTS --------------------

chrome.tabs.onUpdated.addListener((tabId, changeInfo, tab) => {
    // Detect ONLY after page fully loads
    if (changeInfo.status === "complete" && tab.url) {
        debounceCheck(tabId, tab.url);
    }
});

// -------------------- DEBOUNCE --------------------

function debounceCheck(tabId, url) {
    // Clear previous debounce if exists
    if (debounceTimers.has(tabId)) {
        clearTimeout(debounceTimers.get(tabId));
    }

    // Delay detection slightly to avoid duplicate triggers
    const timer = setTimeout(() => {
        checkUrl(tabId, url);
    }, 600);

    debounceTimers.set(tabId, timer);
}

// -------------------- CORE LOGIC --------------------

async function checkUrl(tabId, url) {
    // Ignore internal browser URLs
    if (!url.startsWith("http")) return;

    // Avoid duplicate checks for same tab + URL
    if (lastCheckedPerTab.get(tabId) === url) return;
    lastCheckedPerTab.set(tabId, url);

    try {
        const response = await fetch("http://127.0.0.1:8000/predict", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ url })
        });

        const data = await response.json();

        // Defensive validation
        if (!data || typeof data.label !== "number") {
            console.warn("Invalid API response:", data);
            return;
        }

        // -------------------- PHISHING --------------------
        if (data.label === 1) {
            // Badge
            chrome.action.setBadgeText({ tabId, text: "ALERT" });
            chrome.action.setBadgeBackgroundColor({ tabId, color: "#ef4444" });

            // Notification (only for danger)
            chrome.notifications.create({
                type: "basic",
                iconUrl: "https://cdn-icons-png.flaticon.com/512/564/564619.png",
                title: "⚠️ Phishing Alert",
                message: "This website may be a phishing site!"
            });
        }

        // -------------------- LEGITIMATE --------------------
        else {
            // Badge only (no notification → good UX)
            chrome.action.setBadgeText({ tabId, text: "SAFE" });
            chrome.action.setBadgeBackgroundColor({ tabId, color: "#22c55e" });
        }

    } catch (err) {
        // Fail silently (do not disturb user)
        console.warn("Phishing detection skipped:", err);
    }
}
