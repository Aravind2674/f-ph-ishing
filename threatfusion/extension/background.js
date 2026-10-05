// ThreatFusion service worker (MV3, B15).
//
// On every top-level navigation it asks the user's own backend (localhost) for the FAST-tier verdict — local lists, the brand
// check and the URL-text models; nothing about the page is sent to any third party — and shows a toolbar badge. The content script
// (content.js) asks this worker for the verdict of its tab and draws the warning banner.
import {
  API_BASE, VerdictCache, apiHeaders, badgeFor, checkable, fastRequestBody, feedbackBody, needsBanner,
} from "./lib.mjs";

const cache = new VerdictCache();
const verdictByTab = new Map(); // tabId -> { page, verdict }
const dismissed = new Set(); // hosts the user dismissed this session
const pending = new Set(); // tabIds whose fast check is still running (the content script waits for them)

async function settings() {
  const v = await chrome.storage.local.get(["tfApiToken", "tfFullUrl", "tfAutoCheck"]);
  return { token: v.tfApiToken || "", fullUrl: !!v.tfFullUrl, auto: v.tfAutoCheck !== false };
}

async function fastCheck(page, { token, fullUrl }) {
  const key = fullUrl ? page.url : page.host;
  const cached = cache.get(key);
  if (cached) return cached;
  const response = await fetch(`${API_BASE}/scan/fast`, {
    method: "POST",
    headers: apiHeaders(token),
    body: JSON.stringify(fastRequestBody(page, { fullUrl })),
  });
  if (!response.ok) throw new Error(`fast tier ${response.status}`);
  const verdict = await response.json();
  cache.set(key, verdict);
  return verdict;
}

function paint(tabId, verdict) {
  const b = badgeFor(verdict);
  chrome.action.setBadgeText({ tabId, text: b.text });
  chrome.action.setBadgeBackgroundColor({ tabId, color: "#000000" }); // monochrome: the glyph carries the meaning, not colour
  chrome.action.setTitle({ tabId, title: b.title });
}

chrome.webNavigation.onCommitted.addListener(async (details) => {
  if (details.frameId !== 0) return; // top-level navigations only
  const page = checkable(details.url);
  verdictByTab.delete(details.tabId);
  if (!page) {
    paint(details.tabId, null);
    return;
  }
  pending.add(details.tabId);
  try {
    const s = await settings();
    if (!s.auto || !s.token) {
      paint(details.tabId, null); // no token yet: say nothing rather than guess
      return;
    }
    const verdict = await fastCheck(page, s);
    verdictByTab.set(details.tabId, { page, verdict });
    paint(details.tabId, verdict);
  } catch (err) {
    verdictByTab.delete(details.tabId);
    paint(details.tabId, null); // backend offline / rejected: no badge — an outage is not a clean result, and not an alarm
  } finally {
    pending.delete(details.tabId);
  }
});

chrome.tabs.onRemoved.addListener((tabId) => verdictByTab.delete(tabId));

chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
  const tabId = sender.tab && sender.tab.id;
  if (message.type === "getVerdict") {
    const entry = verdictByTab.get(tabId);
    const show = entry && needsBanner(entry.verdict) && !dismissed.has(entry.page.host);
    sendResponse({ show: !!show, pending: pending.has(tabId), verdict: show ? entry.verdict : null, host: entry ? entry.page.host : null });
    return false;
  }
  if (message.type === "dismiss") {
    if (message.host) dismissed.add(message.host);
    sendResponse({ ok: true });
    return false;
  }
  if (message.type === "report") {
    (async () => {
      const entry = verdictByTab.get(tabId);
      const s = await settings();
      if (!entry) return sendResponse({ ok: false, error: "no verdict for this tab" });
      try {
        const r = await fetch(`${API_BASE}/feedback`, {
          method: "POST",
          headers: apiHeaders(s.token),
          body: JSON.stringify(feedbackBody(entry.page, entry.verdict, message.label || "false_positive", { fullUrl: s.fullUrl, note: message.note })),
        });
        sendResponse({ ok: r.ok, status: r.status });
      } catch (err) {
        sendResponse({ ok: false, error: "backend not reachable" });
      }
    })();
    return true; // async response
  }
  return false;
});
