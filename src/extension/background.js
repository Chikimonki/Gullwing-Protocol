// Gullwing Browser Extension — v1.1
// Download guard + Back button hijacking detection
const GULLWING_API = "http://127.0.0.1:9393";

const RISK_ICONS = {
    "CLEAR": "🟢",
    "NOTABLE": "🟡",
    "SUSPICIOUS": "🟠",
    "HOSTILE": "🔴"
};

// ============================================================================
//  BACK BUTTON HIJACKING DETECTION
// ============================================================================

let navigationHistory = [];
let backButtonTraps = new Set();
const TRAP_THRESHOLD = 3;  // Same URL 3+ times via back button = trap
const TRAP_WINDOW = 5000;   // Within 5 seconds

// Monitor all navigation events
chrome.webNavigation.onCommitted.addListener((details) => {
    // Only track top-level frames (not iframes)
    if (details.frameId !== 0) return;
    
    const now = Date.now();
    const url = details.url;
    const transition = details.transitionType;
    
    // Record this navigation
    navigationHistory.push({ url, time: now, transition });
    
    // Clean old entries
    navigationHistory = navigationHistory.filter(e => now - e.time < TRAP_WINDOW);
    
    // Detect back button traps
    if (transition === "auto_subframe" || transition === "manual_subframe") return;
    
    // Count how many times we've hit this URL via back/forward/reload
    const recentVisits = navigationHistory.filter(e => 
        e.url === url && 
        (e.transition === "reload" || e.transition === "link" || e.transition === "typed")
    );
    
    if (recentVisits.length >= TRAP_THRESHOLD) {
        if (!backButtonTraps.has(url)) {
            backButtonTraps.add(url);
            
            chrome.notifications.create({
                type: "basic",
                iconUrl: "icon.png",
                title: "🔴 Back Button Trap Detected",
                message: `Site forcing repeated visits: ${url.substring(0, 80)}\n\nThis site may be hijacking your back button. Close the tab immediately.`,
                priority: 2,
                buttons: [{ title: "Close tab" }]
            });
            
            console.warn("GULLWING: Back button trap detected:", url);
        }
    }
});

// Handle notification button click — close the trapped tab
chrome.notifications.onButtonClicked.addListener((notificationId, buttonIndex) => {
    if (buttonIndex === 0) {
        // Find and close tabs with the trapped URL
        chrome.tabs.query({ active: true, currentWindow: true }, (tabs) => {
            if (tabs[0]) {
                chrome.tabs.remove(tabs[0].id);
            }
        });
    }
});

// Reset trap tracking when user navigates to a genuinely new page
chrome.webNavigation.onBeforeNavigate.addListener((details) => {
    if (details.frameId === 0) {
        // User typed a new URL or clicked a real link — clear trap state
        backButtonTraps.delete(details.url);
    }
});

// ============================================================================
//  DOWNLOAD GUARD
// ============================================================================

chrome.downloads.onChanged.addListener(async (delta) => {
    if (delta.state && delta.state.current === "complete") {
        const [download] = await chrome.downloads.search({ id: delta.id });
        if (!download || !download.filename) return;
        
        // Analyze everything — Gullwing's extractor finds hidden executables
        let wslPath = download.filename;
        if (wslPath.match(/^[A-Z]:\\/)) {
            wslPath = "/mnt/" + wslPath[0].toLowerCase() + wslPath.substring(2).replace(/\\/g, "/");
        }
        
        try {
            await analyzeDownload(download, wslPath);
        } catch (err) {
            console.error("Gullwing analysis failed:", err);
        }
    }
});

async function analyzeDownload(download, wslPath) {
    const filename = download.filename.split("/").pop() || download.filename;
    
    // Check if Gullwing API is reachable
    try {
        const statusRes = await fetch(`${GULLWING_API}/status`);
        if (!statusRes.ok) throw new Error("API not reachable");
    } catch {
        console.log("Gullwing API not running — skipping analysis");
        return;
    }

    const formBody = "path=" + encodeURIComponent(wslPath);
    
    let result;
    try {
        const res = await fetch(`${GULLWING_API}/reflect`, {
            method: "POST",
            headers: { "Content-Type": "application/x-www-form-urlencoded" },
            body: formBody
        });
        result = await res.json();
    } catch (err) {
        showNotification(filename, "⚠️", "Analysis failed", "Gullwing API error");
        return;
    }

    const convergence = result.convergence || {};
    const ml = result.ml || {};
    const identity = result.identity || {};
    const riskTier = convergence.risk_tier || "UNKNOWN";
    const className = ml.class || "unknown";
    const confidence = ml.confidence || 0;
    const signals = convergence.signals || [];
    const sha256 = (identity.sha256 || "").substring(0, 16);

    const icon = RISK_ICONS[riskTier] || "❓";
    
    let message = `${icon} ${riskTier} — ${className}`;
    let contextMessage = "";
    
    if (riskTier === "HOSTILE" || riskTier === "SUSPICIOUS") {
        contextMessage = `⚠️ WARNING: ${signals.slice(0, 2).join(", ")}`;
    } else if (convergence.novelty_tier === "EXTREME") {
        contextMessage = `Novel binary — ${confidence.toFixed(0)}% confidence as ${className}`;
    } else {
        contextMessage = `${confidence.toFixed(0)}% confidence — SHA256: ${sha256}…`;
    }

    showNotification(filename, icon, message, contextMessage);
}

function showNotification(filename, icon, title, message) {
    chrome.notifications.create({
        type: "basic",
        iconUrl: "icon.png",
        title: `${icon} ${filename}`,
        message: `${title}\n${message}`,
        priority: 1
    });
}

// Heartbeat — keep service worker alive
setInterval(() => {
    console.log("Gullwing heartbeat", Date.now());
}, 20000);

chrome.runtime.onInstalled.addListener(() => {
    console.log("Gullwing Extension v1.1 — Download guard + Back button protection");
});
