/**
 * PhishGuard V2 - Background Service Worker
 *
 * Handles navigation-based scans, blocking, and temporary allow-listing
 * requests from the blocked page.
 */

const TEMP_ALLOW_KEY = "temporaryAllowedUrls";
const DEFAULT_API_BASE = "http://127.0.0.1:8765";
const BLOCK_PAGE = chrome.runtime.getURL("blocked.html");
const DEFAULT_ICON = {
  16: "logo.png",
  32: "logo.png",
  48: "logo.png",
  128: "logo.png",
};
const BADGE_COLORS = {
  safe: "#3f3f46",
  suspicious: "#3f3f46",
  phishing: "#3f3f46",
  error: "#3f3f46",
};

function normalizeUrl(url) {
  try {
    const urlObj = new URL(url);
    urlObj.hash = "";
    return urlObj.href;
  } catch {
    return url || "";
  }
}

function normalizeApiBase(url) {
  const trimmed = (url || "").trim();
  if (!trimmed) {
    return DEFAULT_API_BASE;
  }
  return trimmed.replace(/\/+$/, "");
}

function buildApiEndpoint(baseUrl, path) {
  return new URL(path, normalizeApiBase(baseUrl) + "/").toString();
}

async function isTemporarilyAllowed(url) {
  const normalized = normalizeUrl(url);
  const { [TEMP_ALLOW_KEY]: entries = [] } = await chrome.storage.session.get([TEMP_ALLOW_KEY]);
  const now = Date.now();

  const isAllowed = entries.some((entry) => {
    if (!entry || !entry.url || !entry.expiresAt) {
      return false;
    }
    return entry.expiresAt > now && normalizeUrl(entry.url) === normalized;
  });

  const freshEntries = entries.filter((entry) => entry && entry.url && entry.expiresAt > now);
  if (freshEntries.length !== entries.length) {
    await chrome.storage.session.set({ [TEMP_ALLOW_KEY]: freshEntries });
  }

  return isAllowed;
}

async function getApiBase() {
  const { apiBaseUrl } = await chrome.storage.local.get(["apiBaseUrl"]);
  return normalizeApiBase(apiBaseUrl);
}

async function storeScanResult(url, result) {
  await chrome.storage.session.set({
    lastScannedUrl: normalizeUrl(url),
    lastScanResult: result,
  });

  await updateBadge(result);
}

async function updateBadge(result) {
  if (!chrome.action) {
    return;
  }

  const riskLevel = result?.risk_level || "error";
  const badgeColor = BADGE_COLORS[riskLevel] || BADGE_COLORS.error;
  await chrome.action.setBadgeBackgroundColor({ color: badgeColor });
  await chrome.action.setIcon({ path: DEFAULT_ICON });

  if (riskLevel === "safe") {
    await chrome.action.setBadgeText({ text: "✅" });
  } else if (riskLevel === "phishing") {
    await chrome.action.setBadgeText({ text: "❗" });
  } else if (riskLevel === "suspicious") {
    await chrome.action.setBadgeText({ text: "⚠" });
  } else {
    await chrome.action.setBadgeText({ text: "" });
  }
}

async function scanUrl(url, htmlContent = null) {
  const apiBase = await getApiBase();
  const endpoint = buildApiEndpoint(apiBase, "/v2/predict");
  const response = await fetch(endpoint, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({
      url: normalizeUrl(url),
      html_content: htmlContent,
    }),
  });

  const text = await response.text();
  if (!response.ok) {
    throw new Error(text || `API error: ${response.status}`);
  }

  return JSON.parse(text);
}

async function maybeBlockTab(tabId, tabUrl, result) {
  const { blockPhishing = true } = await chrome.storage.local.get(["blockPhishing"]);
  if (!blockPhishing || result.risk_level !== "phishing") {
    return;
  }

  const targetUrl = chrome.runtime.getURL(
    `blocked.html?url=${encodeURIComponent(normalizeUrl(tabUrl))}` +
      `&risk_score=${encodeURIComponent(String(result.risk_score ?? ""))}` +
      `&explanation=${encodeURIComponent(result.explanation || "")}`
  );

  await chrome.tabs.update(tabId, { url: targetUrl });
}

async function scanAndMaybeBlock(tabId, tabUrl) {
  if (!tabUrl || !/^https?:/i.test(tabUrl)) {
    return;
  }

  if (tabUrl.startsWith(BLOCK_PAGE)) {
    return;
  }

  if (await isTemporarilyAllowed(tabUrl)) {
    return;
  }

  const result = await scanUrl(tabUrl);
  await storeScanResult(tabUrl, result);
  await maybeBlockTab(tabId, tabUrl, result);
}

async function cleanupExpiredAllowances() {
  const { [TEMP_ALLOW_KEY]: entries = [] } = await chrome.storage.session.get([TEMP_ALLOW_KEY]);
  const now = Date.now();
  const freshEntries = entries.filter((entry) => entry && entry.url && entry.expiresAt > now);

  if (freshEntries.length !== entries.length) {
    await chrome.storage.session.set({ [TEMP_ALLOW_KEY]: freshEntries });
  }
}

async function clearBadge() {
  if (!chrome.action) {
    return;
  }
  await chrome.action.setBadgeText({ text: "" });
}

async function refreshActionIcon() {
  if (!chrome.action) {
    return;
  }
  await chrome.action.setIcon({ path: DEFAULT_ICON });
}

chrome.runtime.onInstalled.addListener(() => {
  refreshActionIcon().catch((error) => {
    console.warn("[PhishGuard] Failed to set action icon on install:", error);
  });
  cleanupExpiredAllowances().catch((error) => {
    console.warn("[PhishGuard] Failed to clean temporary allowances on install:", error);
  });
  clearBadge().catch(() => {});
});

chrome.runtime.onStartup.addListener(() => {
  refreshActionIcon().catch((error) => {
    console.warn("[PhishGuard] Failed to set action icon on startup:", error);
  });
  cleanupExpiredAllowances().catch((error) => {
    console.warn("[PhishGuard] Failed to clean temporary allowances on startup:", error);
  });
  clearBadge().catch(() => {});
});

chrome.tabs.onUpdated.addListener((tabId, changeInfo, tab) => {
  if (changeInfo.status !== "complete" || !tab || !tab.url) {
    return;
  }

  chrome.storage.local.get(["scanOnNavigate"]).then(({ scanOnNavigate = true }) => {
    if (!scanOnNavigate) {
      return;
    }

    scanAndMaybeBlock(tabId, tab.url).catch((error) => {
      console.warn("[PhishGuard] Auto-scan failed:", error);
      clearBadge().catch(() => {});
    });
  });
});

chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
  if (!message || message.type !== "TEMP_ALLOW_URL" || !message.url) {
    return false;
  }

  (async () => {
    const { [TEMP_ALLOW_KEY]: entries = [] } = await chrome.storage.session.get([TEMP_ALLOW_KEY]);
    const expiresAt = Date.now() + (message.ttlMs || 15 * 60 * 1000);

    const nextEntries = entries
      .filter((entry) => entry && entry.url !== message.url && entry.expiresAt > Date.now())
      .concat({ url: message.url, expiresAt });

    await chrome.storage.session.set({ [TEMP_ALLOW_KEY]: nextEntries });
    await clearBadge();
    sendResponse({ ok: true });
  })().catch((error) => {
    console.error("[PhishGuard] Failed to store temporary allowance:", error);
    sendResponse({ ok: false, error: error.message });
  });

  return true;
});
