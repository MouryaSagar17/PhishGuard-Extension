/**
 * PhishGuard V2 - Popup UI
 * 
 * Enhanced features:
 *   - Risk levels (Safe, Suspicious, Phishing)
 *   - Feature importance explanation
 *   - Improved confidence visualization
 *   - Scan history with timeline
 *   - Real-time status indicator
 */

// DOM Elements
const statusBadge = document.getElementById("statusBadge");
const scanBtn = document.getElementById("scanBtn");
const scanBtnText = document.getElementById("scanBtnText");
const scanSpinner = document.getElementById("scanSpinner");
const demoBtn = document.getElementById("demoBtn");
const resultCard = document.getElementById("resultCard");
const resultTitle = document.getElementById("resultTitle");
const resultDetail = document.getElementById("resultDetail");
const resultIcon = document.getElementById("resultIcon");
const confidenceContainer = document.getElementById("confidenceContainer");
const confidencePercent = document.getElementById("confidencePercent");
const confidenceBarFill = document.getElementById("confidenceBarFill");
const explanationContainer = document.getElementById("explanationContainer");
const explanationText = document.getElementById("explanationText");
const topFeaturesContainer = document.getElementById("topFeaturesContainer");
const topFeaturesList = document.getElementById("topFeaturesList");
const indicatorsContainer = document.getElementById("indicatorsContainer");
const indicatorsList = document.getElementById("indicatorsList");
const errorEl = document.getElementById("error");
const currentUrlEl = document.getElementById("currentUrl");
const apiBaseInput = document.getElementById("apiBase");
const autoScanInput = document.getElementById("autoScan");
const blockPhishingInput = document.getElementById("blockPhishing");
const demoModeInput = document.getElementById("demoMode");
const historyList = document.getElementById("historyList");
const clearHistoryBtn = document.getElementById("clearHistoryBtn");
const debugInfo = document.getElementById("debugInfo");
const debugText = document.getElementById("debugText");

// State
let isScanning = false;
let currentRiskLevel = null;
let listenersInitialized = false;
const MAX_HISTORY = 10;

// ========== UI State Management ==========

function normalizeUrl(url) {
  try {
    const urlObj = new URL(url);
    urlObj.hash = "";
    return urlObj.href;
  } catch {
    return url.split("#")[0];
  }
}

function normalizeApiBase(url) {
  const trimmed = (url || "").trim();
  if (!trimmed) {
    return "http://127.0.0.1:8765";
  }
  return trimmed.replace(/\/+$/, "");
}

function buildApiEndpoint(baseUrl, path) {
  return new URL(path, normalizeApiBase(baseUrl) + "/").toString();
}

function buildBlockPageUrl(url, riskScore, explanation) {
  const base = chrome.runtime.getURL("blocked.html");
  const params = new URLSearchParams({
    url,
    u: url,
    risk_score: String(riskScore ?? ""),
    explanation: explanation || "",
  });
  return `${base}?${params.toString()}`;
}

async function checkApiHealth(baseUrl) {
  const endpoint = buildApiEndpoint(baseUrl, "/health");
  const response = await fetch(endpoint, { method: "GET" });
  if (!response.ok) {
    const body = await response.text().catch(() => "");
    throw new Error(body || `Health check failed (${response.status})`);
  }
  return response.json().catch(() => ({}));
}

function updateStatus(status) {
  statusBadge.textContent = `● ${status}`;
  statusBadge.className = "status-badge";
  
  if (status === "Scanning") {
    statusBadge.classList.add("status-scanning");
  } else if (status === "Safe") {
    statusBadge.classList.add("status-safe");
  } else if (status === "Suspicious") {
    statusBadge.classList.add("status-suspicious");
  } else if (status === "Phishing") {
    statusBadge.classList.add("status-danger");
  }
}

function showError(msg) {
  errorEl.textContent = msg;
  errorEl.classList.remove("hidden");
  resultCard.classList.add("hidden");
  updateStatus("Error");
}

function hideError() {
  errorEl.textContent = "";
  errorEl.classList.add("hidden");
}

function setScanning(scanning) {
  isScanning = scanning;
  isScanning = scanning;
  scanBtn.disabled = scanning;
  
  if (scanning) {
    scanBtnText.textContent = "Scanning…";
    scanSpinner.classList.remove("hidden");
    updateStatus("Scanning");
  } else {
    scanBtnText.textContent = "🔍 Scan Now";
    scanSpinner.classList.add("hidden");
  }
}

// ========== Risk Level Handling ==========

function getRiskLevelInfo(riskLevel, riskScore) {
  const riskLevels = {
    safe: {
      emoji: "✅",
      title: "Safe Website",
      description: "This page appears safe. Low risk of phishing.",
      color: "#28a745",
      bgColor: "#d4edda",
      borderColor: "#c3e6cb"
    },
    suspicious: {
      emoji: "⚠️",
      title: "⚠️ Suspicious Website",
      description: "This page has some suspicious characteristics. Use caution.",
      color: "#ff9800",
      bgColor: "#fff3cd",
      borderColor: "#ffc107"
    },
    phishing: {
      emoji: "❗",
      title: "🚨 Phishing Detected",
      description: "This page is likely a phishing attack. Avoid entering credentials.",
      color: "#dc3545",
      bgColor: "#f8d7da",
      borderColor: "#f5c6cb"
    }
  };
  
  return riskLevels[riskLevel] || riskLevels.suspicious;
}

// ========== Feature Explanations ==========

function displayTopFeatures(topFeatures) {
  if (!topFeatures || topFeatures.length === 0) {
    topFeaturesContainer.classList.add("hidden");
    return;
  }
  
  topFeaturesContainer.classList.remove("hidden");
  topFeaturesList.innerHTML = "";
  
  // Map feature names to user-friendly descriptions
  const featureDescriptions = {
    "use_ip": "URL uses IP address",
    "domain_very_new": "Domain registered recently",
    "domain_suspicious_age": "Domain age seems suspicious",
    "scheme_https": "Uses HTTPS protocol",
    "has_valid_ssl": "Valid SSL certificate",
    "suspicious_hits": "Suspicious keywords detected",
    "tld_suspicious": "Suspicious TLD",
    "ssl_cert_expires_soon": "SSL cert expires soon",
    "suspicious_dns": "DNS lookup failed",
    "obfuscated_js": "Obfuscated JavaScript",
    "form_action_mismatch": "Form submits to different domain",
    "login_form_count": "Login form detected",
    "suspicious_iframe_count": "External iframes detected",
    "external_script_count": "External scripts loaded",
    "estimated_redirects": "Multiple redirects detected"
  };
  
  topFeatures.slice(0, 5).forEach(feature => {
    const item = document.createElement("div");
    item.className = "feature-item";
    
    const direction = feature.contribution_direction === "positive" ? "⬆️" : "⬇️";
    const description = featureDescriptions[feature.feature_name] || feature.feature_name;
    const magnitude = feature.contribution_magnitude.toFixed(3);
    
    item.innerHTML = `
      <span class="feature-direction">${direction}</span>
      <span class="feature-name">${description}</span>
      <span class="feature-magnitude">${magnitude}</span>
    `;
    
    topFeaturesList.appendChild(item);
  });
}

// ========== Result Display ==========

function showResult(riskLevel, riskScore, confidence, explanation, topFeatures, url) {
  hideError();
  resultCard.classList.remove("hidden");
  if (currentUrlEl) {
    currentUrlEl.textContent = url;
  }
  
  const riskInfo = getRiskLevelInfo(riskLevel, riskScore);
  currentRiskLevel = riskLevel;
  
  // Update UI styling based on risk level
  resultCard.style.backgroundColor = riskInfo.bgColor;
  resultCard.style.borderColor = riskInfo.borderColor;
  resultCard.style.borderWidth = "2px";
  
  resultIcon.textContent = riskInfo.emoji;
  resultTitle.textContent = riskInfo.title;
  resultDetail.textContent = riskInfo.description;
  
  updateStatus(riskLevel === "safe" ? "Safe" : riskLevel === "suspicious" ? "Suspicious" : "Phishing");
  
  // Risk score display - show phishing probability (0-40 Safe, 40-70 Suspicious, 70-100 Phishing)
  const riskScorePercent = Math.round(riskScore * 100);
  
  if (confidenceContainer) {
    confidenceContainer.classList.remove("hidden");
  }

  if (confidenceBarFill) {
    // Bar width shows phishing risk score, color shows risk level
    confidenceBarFill.style.width = `${riskScorePercent}%`;
    confidenceBarFill.style.backgroundColor = riskInfo.color;
    confidenceBarFill.style.boxShadow = `0 0 10px ${riskInfo.color}40`;
  }

  if (confidencePercent) {
    // Display phishing risk percentage based on ranges:
    // 0-40: Safe
    // 40-70: Suspicious
    // 70-100: Phishing
    confidencePercent.textContent = `${riskScorePercent}% Phishing Risk`;
    confidencePercent.style.color = riskInfo.color;  // Set text color dynamically
  }
  
  // Explanation
  if (explanation) {
    explanationContainer.classList.remove("hidden");
    explanationText.textContent = explanation;
  }
  
  // Top contributing features
  displayTopFeatures(topFeatures);
  
  // Trust indicators
  const indicators = generateIndicators(url);
  indicatorsList.innerHTML = "";
  indicators.forEach(ind => {
    const item = document.createElement("div");
    item.className = "indicator-item";
    item.innerHTML = `<span class="indicator-icon">${ind.icon}</span><span>${ind.label}</span>`;
    indicatorsList.appendChild(item);
  });
  indicatorsContainer.classList.remove("hidden");
  
  // Add to history
  addToHistory(url, riskLevel, riskScore);
}

// ========== URL Indicators ==========

function generateIndicators(url) {
  const indicators = [];
  
  try {
    const urlObj = new URL(url);
    
    // HTTPS check
    const isHttps = urlObj.protocol === "https:";
    indicators.push({
      icon: isHttps ? "✅" : "❌",
      label: `HTTPS: ${isHttps ? "Yes" : "No"}`,
    });
    
    // Domain characteristics
    const domain = urlObj.hostname;
    const hasNumbers = /\d/.test(domain);
    const isShortDomain = domain.split(".").length === 2;
    
    if (hasNumbers && !isShortDomain) {
      indicators.push({
        icon: "⚠️",
        label: "Domain: Unusual pattern",
      });
    } else {
      indicators.push({
        icon: "✅",
        label: "Domain: Normal pattern",
      });
    }
    
    // Suspicious patterns
    const suspiciousPatterns = [
      /bit\.ly|tinyurl|short\.link/i,
      /\@/,
      /login|secure|update|verify|confirm|act|urgent/i,
    ];
    
    let hasSuspicious = false;
    for (const pattern of suspiciousPatterns) {
      if (pattern.test(url)) {
        hasSuspicious = true;
        break;
      }
    }
    
    indicators.push({
      icon: hasSuspicious ? "🚨" : "✅",
      label: hasSuspicious ? "Patterns: Suspicious detected" : "Patterns: Clean",
    });
  } catch (e) {
    indicators.push({
      icon: "⚠️",
      label: "URL: Invalid format",
    });
  }
  
  return indicators;
}

// ========== Settings ==========

async function loadSettings() {
  const s = await chrome.storage.local.get([
    "apiBaseUrl",
    "blockPhishing",
    "scanOnNavigate",
    "demoMode",
  ]);
  
  apiBaseInput.value = normalizeApiBase(s.apiBaseUrl || "http://127.0.0.1:8765");
  blockPhishingInput.checked = s.blockPhishing !== false;
  autoScanInput.checked = s.scanOnNavigate !== false;
  demoModeInput.checked = s.demoMode === true;
}

async function saveSettings() {
  await chrome.storage.local.set({
    apiBaseUrl: normalizeApiBase(apiBaseInput.value),
    blockPhishing: blockPhishingInput.checked,
    scanOnNavigate: autoScanInput.checked,
    demoMode: demoModeInput.checked,
  });
}

// ========== History Management ==========

async function addToHistory(url, riskLevel, riskScore) {
  const { scanHistory = [] } = await chrome.storage.local.get(["scanHistory"]);
  
  const item = {
    url,
    riskLevel,
    riskScore,
    timestamp: new Date().toISOString(),
  };
  
  scanHistory.unshift(item);
  if (scanHistory.length > MAX_HISTORY) {
    scanHistory.pop();
  }
  
  await chrome.storage.local.set({ scanHistory });
  await displayHistory();
}

async function displayHistory() {
  const { scanHistory = [] } = await chrome.storage.local.get(["scanHistory"]);
  
  historyList.innerHTML = "";
  
  if (scanHistory.length === 0) {
    historyList.innerHTML = '<p class="history-empty">No scans yet</p>';
    return;
  }
  
  scanHistory.forEach((item, idx) => {
    const historyItem = document.createElement("div");
    historyItem.className = "history-item";
    
    const riskEmojis = {
      safe: "✅",
      suspicious: "⚠️",
      phishing: "❗"
    };
    
    const riskClasses = {
      safe: "history-item-safe",
      suspicious: "history-item-suspicious",
      phishing: "history-item-phishing"
    };
    
    const emoji = riskEmojis[item.riskLevel] || "❓";
    const riskClass = riskClasses[item.riskLevel] || "history-item-safe";
    
    const timeAgo = getTimeAgo(item.timestamp);
    const domain = extractDomain(item.url);
    const riskPercent = Math.round(item.riskScore * 100);
    
    historyItem.innerHTML = `
      <div class="history-item-status ${riskClass}">${emoji}</div>
      <div class="history-item-content">
        <div class="history-item-url" title="${item.url}">${domain}</div>
        <div class="history-item-details">
          <span class="history-item-risk">${item.riskLevel.toUpperCase()}</span>
          <span class="history-item-score">${riskPercent}%</span>
          <span class="history-item-time">${timeAgo}</span>
        </div>
      </div>
    `;
    
    historyItem.addEventListener("click", () => {
      navigator.clipboard.writeText(item.url);
      historyItem.innerHTML += "<p style='margin:5px 0;font-size:12px;color:green;'>Copied!</p>";
      setTimeout(() => location.reload(), 1000);
    });
    
    historyList.appendChild(historyItem);
  });
}

function getTimeAgo(timestamp) {
  const date = new Date(timestamp);
  const now = new Date();
  const seconds = Math.floor((now - date) / 1000);
  
  if (seconds < 60) return "now";
  if (seconds < 3600) return `${Math.floor(seconds / 60)}m ago`;
  if (seconds < 86400) return `${Math.floor(seconds / 3600)}h ago`;
  return `${Math.floor(seconds / 86400)}d ago`;
}

function extractDomain(url) {
  try {
    const urlObj = new URL(url.includes("://") ? url : "http://" + url);
    return urlObj.hostname;
  } catch {
    return url.substring(0, 30) + "…";
  }
}

// ========== Scanning ==========

async function scanCurrentTab() {
  console.log("[PhishGuard] scanCurrentTab called");
  setScanning(true);
  
  try {
    console.log("[PhishGuard] Querying active tab...");
    const tabs = await chrome.tabs.query({ active: true, currentWindow: true });
    
    if (!tabs || tabs.length === 0) {
      throw new Error("No active tab found. Make sure the extension popup is open in the active window.");
    }
    
    const [tab] = tabs;
    console.log("[PhishGuard] Active tab found:", tab.url);
    
    // Check if this is a blocked.html page and extract the original URL
    let scanUrl = tab.url;
    if (tab.url && tab.url.includes("blocked.html")) {
      console.log("[PhishGuard] Detected blocked page, extracting original URL...");
      const urlParams = new URLSearchParams(new URL(tab.url).search);
      const originalUrl = urlParams.get("url") || urlParams.get("u");
      if (originalUrl) {
        scanUrl = originalUrl;
        console.log("[PhishGuard] Original URL extracted:", scanUrl);
      }
    }
    
    const url = normalizeUrl(scanUrl);
    if (currentUrlEl) {
      currentUrlEl.textContent = url;
    }
    
    // Extract HTML content from current tab for multi-modal detection
    let htmlContent = null;
    try {
      console.log("[PhishGuard] Requesting HTML content from content script...");
      const response = await chrome.tabs.sendMessage(tab.id, {
        type: "GET_PAGE_HTML"
      });
      if (response && response.ok) {
        htmlContent = response.html;
        console.log("[PhishGuard] Extracted HTML:", htmlContent.length, "bytes");
      }
    } catch (e) {
      console.log("[PhishGuard] Could not extract HTML content:", e.message);
      // Continue without HTML content
    }
    
    const apiBase = normalizeApiBase(apiBaseInput ? apiBaseInput.value : "http://127.0.0.1:8765");
    console.log("[PhishGuard] API Base URL:", apiBase);

    const endpoint = buildApiEndpoint(apiBase, "/v2/predict");
    console.log("[PhishGuard] Calling endpoint:", endpoint);

    try {
      await checkApiHealth(apiBase);
    } catch (healthError) {
      throw new Error(`Backend not reachable at ${apiBase}: ${healthError.message}`);
    }

    let response;
    try {
      response = await fetch(endpoint, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ 
          url,
          html_content: htmlContent  // Include HTML for multi-modal detection
        })
      });
    } catch (fetchError) {
      console.error("[PhishGuard] Fetch error:", fetchError);
      throw new Error(`Unable to reach API at ${endpoint}: ${fetchError.message}`);
    }

    const responseText = await response.text();
    console.log("[PhishGuard] API Response status:", response.status);
    console.log("[PhishGuard] API Response text:", responseText.substring(0, 200));
    
    if (!response.ok) {
      const errorMsg = responseText || `API error: ${response.status}`;
      console.error("[PhishGuard] API Error:", errorMsg);
      throw new Error(`API Error (${response.status}): ${errorMsg}`);
    }

    let result;
    try {
      result = JSON.parse(responseText);
    } catch (parseError) {
      console.error("[PhishGuard] Response parse error:", parseError);
      throw new Error(`Invalid API response: ${parseError.message}`);
    }
    
    console.log("[PhishGuard] Scan result:", result.risk_level, "Score:", result.risk_score);
    
    showResult(
      result.risk_level,
      result.risk_score,
      result.confidence,
      result.explanation,
      result.top_features,
      url
    );

    await chrome.storage.session.set({
      lastScanResult: result,
      lastScannedUrl: url,
    });

    if (blockPhishingInput && blockPhishingInput.checked && result.risk_level === "phishing") {
      const blockUrl = buildBlockPageUrl(url, result.risk_score, result.explanation);
      await chrome.tabs.update(tab.id, { url: blockUrl });
    }
    
    // Phishing detected - popup displays it without creating new tabs
  } catch (error) {
    console.error("[PhishGuard] Scan error:", error.message, error);
    
    // Show detailed error with debugging hints
    let errorMsg = `Scan failed: ${error.message}`;
    
    // Add helpful hints based on error type
    if (error.message.includes("Unable to reach API")) {
      errorMsg += "\n\n💡 Hint: Check if the backend is running at the API address in Settings.";
    } else if (error.message.includes("No active tab")) {
      errorMsg += "\n\n💡 Hint: Make sure a webpage is active in your browser.";
    }
    
    showError(errorMsg);
    
    // Show debug info
    if (debugInfo) {
      debugInfo.classList.remove("hidden");
      const apiBase = normalizeApiBase(apiBaseInput ? apiBaseInput.value : "http://127.0.0.1:8765");
      debugText.innerHTML = `<small>API: ${apiBase}<br>Status: Connection Error<br>${error.message}</small>`;
    }
  } finally {
    setScanning(false);
  }
}

// ========== Event Listeners ==========

// Initialize event listeners with proper null checks
function initializeEventListeners() {
  if (listenersInitialized) {
    return;
  }
  listenersInitialized = true;

  console.log("[PhishGuard] Initializing event listeners");
  
  // Scan button listener
  if (scanBtn) {
    scanBtn.addEventListener("click", () => {
      console.log("[PhishGuard] Scan button clicked");
      scanCurrentTab();
    });
    console.log("[PhishGuard] Scan button listener attached");
  } else {
    console.error("[PhishGuard] ERROR: scanBtn element not found!");
  }
  
  // Settings listeners
  if (apiBaseInput) {
    apiBaseInput.addEventListener("change", saveSettings);
  }
  if (blockPhishingInput) {
    blockPhishingInput.addEventListener("change", saveSettings);
  }
  if (autoScanInput) {
    autoScanInput.addEventListener("change", saveSettings);
  }
  if (demoModeInput) {
    demoModeInput.addEventListener("change", saveSettings);
  }
  
  // History clear button
  if (clearHistoryBtn) {
    clearHistoryBtn.addEventListener("click", async () => {
      if (confirm("Clear scan history?")) {
        await chrome.storage.local.set({ scanHistory: [] });
        await displayHistory();
      }
    });
  } else {
    console.warn("[PhishGuard] WARNING: clearHistoryBtn element not found");
  }
  
  // Demo button
  if (demoBtn) {
    demoBtn.addEventListener("click", async () => {
      console.log("[PhishGuard] Demo button clicked");
      demoModeInput.checked = !demoModeInput.checked;
      await saveSettings();
      
      // Show demo prediction
      showResult(
        "suspicious",
        0.65,
        0.85,
        "Demo: This page exhibits some phishing characteristics. Suspicious patterns detected.",
        [
          { feature_name: "form_action_mismatch", contribution_magnitude: 0.15, contribution_direction: "positive" },
          { feature_name: "external_script_count", contribution_magnitude: 0.12, contribution_direction: "positive" },
          { feature_name: "login_form_count", contribution_magnitude: 0.10, contribution_direction: "positive" }
        ],
        "https://demo-phishing-example.com/verify/account"
      );
    });
  } else {
    console.warn("[PhishGuard] WARNING: demoBtn element not found");
  }
}

/**
 * Load and display cached auto-scan result if available for current tab
 */
async function loadCachedAutoScanResult() {
  try {
    const tabs = await chrome.tabs.query({ active: true, currentWindow: true });
    if (!tabs || tabs.length === 0) return;
    
    const [tab] = tabs;
    const currentUrl = normalizeUrl(tab.url);
    
    // Get cached scan result from auto-scan
    const { lastScanResult, lastScannedUrl } = await chrome.storage.session.get([
      "lastScanResult",
      "lastScannedUrl"
    ]);
    
    // If we have a cached result for the current URL, display it
    if (lastScanResult && lastScannedUrl && normalizeUrl(lastScannedUrl) === currentUrl) {
      console.log("[PhishGuard] Displaying cached auto-scan result");
      showResult(
        lastScanResult.risk_level,
        lastScanResult.risk_score,
        lastScanResult.confidence,
        lastScanResult.explanation,
        lastScanResult.top_features,
        currentUrl
      );
    }
  } catch (error) {
    console.log("[PhishGuard] Could not load cached result:", error.message);
    // Silently fail - user can scan manually
  }
}

function bootstrapPopup() {
  console.log("[PhishGuard] Bootstrapping popup");

  initializeEventListeners();

  // Load UI state in the background so a transient storage/API issue does not
  // prevent the scan button from working.
  loadSettings().catch((error) => {
    console.error("[PhishGuard] Error loading settings:", error);
  });

  displayHistory().catch((error) => {
    console.error("[PhishGuard] Error loading history:", error);
  });

  loadCachedAutoScanResult().catch((error) => {
    console.error("[PhishGuard] Error loading cached result:", error);
  });
}

if (document.readyState === "loading") {
  document.addEventListener("DOMContentLoaded", bootstrapPopup, { once: true });
} else {
  bootstrapPopup();
}
