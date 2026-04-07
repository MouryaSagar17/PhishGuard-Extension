/**
 * PhishGuard V2 - Content Script
 * 
 * Runs in the context of web pages to:
 * - Extract page HTML for multi-modal detection
 * - Support popup-based scanning
 */

// Listen for messages from background script
chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
  if (message && message.type === "GET_PAGE_HTML") {
    // Send back the current page's HTML content
    // Limit to first 100KB to avoid huge payloads
    const html = document.documentElement.outerHTML;
    const maxSize = 100 * 1024; // 100KB
    const truncatedHtml = html.length > maxSize ? html.substring(0, maxSize) : html;
    
    sendResponse({
      ok: true,
      html: truncatedHtml,
      url: window.location.href,
      title: document.title,
    });
    return true;
  }

  return false;
});

// Log that content script loaded
console.log("[PhishGuard] Content script loaded for:", window.location.hostname);
