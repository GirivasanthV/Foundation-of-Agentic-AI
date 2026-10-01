const DEFAULTS = {
  enabled: true,
  captureScreenshots: true,
  backendUrl: "http://localhost:8000",
  extensionToken: "local-development-token",
  excludedDomains: ["localhost", "127.0.0.1"],
  cooldownMinutes: 5,
};

const scansInProgress = new Set();

async function getSettings() {
  return { ...DEFAULTS, ...(await chrome.storage.local.get(DEFAULTS)) };
}

function isScannable(url, settings) {
  try {
    const parsed = new URL(url);
    if (!["http:", "https:"].includes(parsed.protocol)) return false;
    return !settings.excludedDomains.some((entry) => {
      const excluded = String(entry).trim().toLowerCase();
      return excluded && (parsed.hostname === excluded || parsed.hostname.endsWith(`.${excluded}`));
    });
  } catch {
    return false;
  }
}

async function isCoolingDown(url, minutes) {
  const { scanCache = {} } = await chrome.storage.local.get("scanCache");
  const scannedAt = scanCache[url];
  return Boolean(scannedAt && Date.now() - scannedAt < minutes * 60_000);
}

async function recordScan(url) {
  const { scanCache = {} } = await chrome.storage.local.get("scanCache");
  const entries = Object.entries({ ...scanCache, [url]: Date.now() })
    .sort((a, b) => b[1] - a[1])
    .slice(0, 200);
  await chrome.storage.local.set({ scanCache: Object.fromEntries(entries) });
}

function badgeFor(result, tabId) {
  const score = Number(result.risk_score || 0);
  const color = score >= 70 ? "#e5485c" : score >= 50 ? "#f07843" : score >= 25 ? "#e9b949" : "#26b899";
  chrome.action.setBadgeBackgroundColor({ tabId, color });
  chrome.action.setBadgeText({ tabId, text: String(Math.round(score)) });
  chrome.action.setTitle({ tabId, title: `SentinelAI: ${result.verdict} (${Math.round(score)}/100)` });
}

async function callBackend(path, payload, settings) {
  const response = await fetch(`${settings.backendUrl.replace(/\/$/, "")}${path}`, {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      "X-Extension-Token": settings.extensionToken,
    },
    body: JSON.stringify(payload),
  });
  if (!response.ok) {
    const body = await response.json().catch(() => ({ detail: `Backend returned ${response.status}` }));
    throw new Error(body.detail || `Backend returned ${response.status}`);
  }
  return response.json();
}

async function captureVisibleTab(tab) {
  let lastError;
  for (let attempt = 0; attempt < 3; attempt += 1) {
    try {
      return await chrome.tabs.captureVisibleTab(tab.windowId, { format: "jpeg", quality: 65 });
    } catch (error) {
      lastError = error;
      if (attempt < 2) await new Promise((resolve) => setTimeout(resolve, 500));
    }
  }
  throw lastError;
}

async function scanTab(tab, force = false) {
  const settings = await getSettings();
  if (!settings.enabled || !tab?.id || !tab.url || !tab.active || !isScannable(tab.url, settings)) return;
  if (scansInProgress.has(tab.id)) return;
  if (!force && await isCoolingDown(tab.url, settings.cooldownMinutes)) return;

  scansInProgress.add(tab.id);
  await chrome.action.setBadgeText({ tabId: tab.id, text: "…" });
  await chrome.action.setBadgeBackgroundColor({ tabId: tab.id, color: "#397694" });

  try {
    let screenshotDataUrl = null;
    let screenshotWarning = null;
    if (settings.captureScreenshots) {
      try {
        screenshotDataUrl = await captureVisibleTab(tab);
      } catch (error) {
        const rawMessage = error instanceof Error ? error.message : String(error);
        screenshotWarning = rawMessage.includes("<all_urls>") || rawMessage.includes("activeTab")
          ? "URL/IP analysis completed without a screenshot. Reload the extension and set Site access to On all sites to enable VLM analysis."
          : rawMessage.toLowerCase().includes("cannot be edited")
            ? "URL/IP analysis completed without a screenshot. The tab was being dragged or edited; scan again after releasing it to enable VLM analysis."
          : `URL/IP analysis completed, but screenshot capture failed: ${rawMessage}`;
      }
    }
    const result = await callBackend("/api/v1/extension/analyze-page", {
      url: tab.url,
      title: tab.title || "",
      screenshot_data_url: screenshotDataUrl,
    }, settings);
    await chrome.storage.local.set({
      [`result_${tab.id}`]: result,
      lastResult: result,
      lastError: screenshotWarning,
    });
    await recordScan(tab.url);
    badgeFor(result, tab.id);

    if (["HIGH", "CRITICAL"].includes(result.verdict)) {
      await chrome.notifications.create({
        type: "basic",
        iconUrl: "shield.svg",
        title: `SentinelAI ${result.verdict} warning`,
        message: `${result.normalized_indicator} scored ${Math.round(result.risk_score)}/100. Review before entering information.`,
        priority: 2,
      });
    }
  } catch (error) {
    const rawMessage = error instanceof Error ? error.message : String(error);
    const message = rawMessage.includes("<all_urls>") || rawMessage.includes("activeTab")
      ? "Screenshot permission is missing. Reload the extension and set Site access to On all sites."
      : rawMessage;
    await chrome.storage.local.set({ lastError: message });
    await chrome.action.setBadgeBackgroundColor({ tabId: tab.id, color: "#7f3442" });
    await chrome.action.setBadgeText({ tabId: tab.id, text: "!" });
  } finally {
    scansInProgress.delete(tab.id);
  }
}

chrome.runtime.onInstalled.addListener(async () => {
  const existing = await chrome.storage.local.get(Object.keys(DEFAULTS));
  await chrome.storage.local.set({ ...DEFAULTS, ...existing });
});

chrome.tabs.onUpdated.addListener((_, changeInfo, tab) => {
  if (changeInfo.status === "complete" && tab.active) void scanTab(tab);
});

chrome.tabs.onActivated.addListener(async ({ tabId }) => {
  try {
    void scanTab(await chrome.tabs.get(tabId));
  } catch {
    // The tab may have closed before it could be queried.
  }
});

chrome.runtime.onMessage.addListener((message, _sender, sendResponse) => {
  if (message.type === "SCAN_CURRENT_TAB") {
    chrome.tabs.query({ active: true, currentWindow: true })
      .then(([tab]) => scanTab(tab, true))
      .then(() => sendResponse({ ok: true }))
      .catch((error) => sendResponse({ ok: false, error: String(error) }));
    return true;
  }
  if (message.type === "ANALYZE_HASH") {
    getSettings()
      .then((settings) => callBackend("/api/v1/extension/analyze-hash", message.payload, settings))
      .then((result) => sendResponse({ ok: true, result }))
      .catch((error) => sendResponse({ ok: false, error: error instanceof Error ? error.message : String(error) }));
    return true;
  }
  return false;
});
