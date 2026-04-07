/**
 * PhishGuard V2 - Blocked Page Script
 * Drives the centered phishing warning page.
 */

const params = new URLSearchParams(window.location.search);
const blockedUrl = params.get("url") || params.get("u") || "(Unknown URL)";
const riskScore = parseFloat(params.get("risk_score") || params.get("p") || "");
const explanationText =
  params.get("explanation") ||
  "This tool uses machine learning and can be wrong. Verify the domain with a trusted source before proceeding.";

const blockedUrlEl = document.getElementById("blockedUrl");
const riskLabelEl = document.getElementById("riskLabel");
const explanationEl = document.getElementById("explanation");
const backBtn = document.getElementById("backBtn");
const proceedBtn = document.getElementById("proceedBtn");
const demoLink = document.getElementById("demoLink");

function getRiskLabel(score) {
  if (Number.isNaN(score)) {
    return "❗ Phishing (70-100%) - High risk";
  }

  const pct = Math.round(score * 100);
  if (score < 0.4) return `✅ Safe (0-40%) - ${pct}% risk`;
  if (score < 0.7) return `⚠️ Suspicious (40-70%) - ${pct}% risk`;
  return `❗ Phishing (70-100%) - ${pct}% risk`;
}

blockedUrlEl.textContent = blockedUrl;
riskLabelEl.textContent = getRiskLabel(riskScore);
explanationEl.textContent = explanationText;

backBtn.addEventListener("click", () => {
  if (window.history.length > 1) {
    window.history.back();
    return;
  }
  window.location.href = "about:blank";
});

proceedBtn.addEventListener("click", () => {
  if (!blockedUrl || blockedUrl === "(Unknown URL)") {
    return;
  }

  chrome.runtime.sendMessage(
    {
      type: "TEMP_ALLOW_URL",
      url: blockedUrl,
      ttlMs: 15 * 60 * 1000
    },
    (response) => {
      if (response && response.ok) {
        window.location.href = blockedUrl;
      }
    }
  );
});

if (demoLink) {
  demoLink.addEventListener("click", (event) => {
    event.preventDefault();
    chrome.tabs.create({ url: chrome.runtime.getURL("popup.html") });
  });
}

document.addEventListener("keydown", (e) => {
  if (e.key === "Escape") {
    backBtn.click();
  }
});
