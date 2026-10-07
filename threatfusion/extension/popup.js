import { API_BASE, apiHeaders, checkable, dashboardLink, fastRequestBody, popupView } from "./lib.mjs";

const $ = (id) => document.getElementById(id);
const targetEl = $("target");
const scanBtn = $("scan");
const errorEl = $("error");
const resultEl = $("result");

let page = null;
let token = "";
let fullUrl = false;

const showError = (message) => {
  errorEl.textContent = message;
  errorEl.hidden = !message;
};

chrome.storage.local.get(["tfApiToken", "tfFullUrl"], (v) => {
  token = v.tfApiToken || "";
  fullUrl = !!v.tfFullUrl;
  $("full-url").checked = fullUrl;
  $("token").placeholder = token ? "•••••••• (saved)" : "Paste token";
  $("token-box").open = !token; // the token is the one thing the popup cannot work without
});

$("full-url").addEventListener("change", (e) => {
  fullUrl = e.target.checked;
  chrome.storage.local.set({ tfFullUrl: fullUrl });
});

$("token-save").addEventListener("click", () => {
  token = $("token").value.trim();
  chrome.storage.local.set({ tfApiToken: token }, () => {
    $("token").value = "";
    $("token").placeholder = token ? "•••••••• (saved)" : "Paste token";
  });
});

chrome.tabs.query({ active: true, currentWindow: true }, (tabs) => {
  const url = tabs[0] && tabs[0].url;
  page = url ? checkable(url) : null; // only public web pages are ever scanned
  targetEl.textContent = page ? page.host : "This page cannot be scanned";
  scanBtn.disabled = !page;
});

scanBtn.addEventListener("click", async () => {
  if (!page) return;
  scanBtn.disabled = true;
  scanBtn.textContent = "Scanning…";
  showError("");
  resultEl.hidden = true;
  try {
    const response = await fetch(`${API_BASE}/scan`, {
      method: "POST",
      headers: apiHeaders(token),
      body: JSON.stringify(fastRequestBody(page, { fullUrl })),
    });
    const data = await response.json().catch(() => ({}));
    if (response.status === 401) throw new Error("API token missing or invalid — paste it below (python -m app.core.auth)");
    if (!response.ok || !data.success) throw new Error(data.error || data.detail || `Server error ${response.status}`);

    const view = popupView(data.result);
    const band = $("band");
    band.textContent = view.band;
    band.className = `band ${view.band.toLowerCase()}`;
    $("reasons").replaceChildren(...view.reasons.map((text) => Object.assign(document.createElement("li"), { textContent: text })));
    $("open").href = dashboardLink(page, { fullUrl });
    resultEl.hidden = false;
  } catch (err) {
    showError(err instanceof TypeError ? "Backend not reachable — start it on 127.0.0.1:8000" : err.message);
  } finally {
    scanBtn.disabled = false;
    scanBtn.textContent = "Scan";
  }
});
