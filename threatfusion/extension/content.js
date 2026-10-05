// ThreatFusion content script (B15). Inert unless the service worker says the page needs a warning.
//
// It reads NOTHING from the page except whether password fields exist (to outline them on a flagged site) and never sends any
// page content anywhere. The banner lives in a closed Shadow DOM so the page's own CSS cannot hide or restyle it.
(() => {
  if (window.top !== window) return; // top frame only
  if (window.__tfBanner) return;
  window.__tfBanner = true;

  const headline = (v) => {
    if (v.level === "block") return "This page is on a phishing list.";
    const m = v.brand_check && v.brand_check.match;
    if (m) return `This site may be pretending to be ${m.brand}. The real site is ${m.brand_domain}.`;
    return "This page looks suspicious.";
  };

  function banner(verdict, host) {
    const holder = document.createElement("div");
    holder.setAttribute("data-threatfusion", "banner");
    const root = holder.attachShadow({ mode: "closed" });
    const reasons = (verdict.reasons || []).slice(0, 3);
    root.innerHTML = `
      <style>
        :host { all: initial; }
        .bar { position: fixed; z-index: 2147483647; top: 0; left: 0; right: 0; background: #fff; color: #000; border-bottom: 2px solid #000;
               font: 14px/1.4 system-ui, sans-serif; padding: 10px 16px; display: flex; gap: 16px; align-items: flex-start; }
        .tag { font: 700 11px/1 ui-monospace, monospace; letter-spacing: .08em; border: 2px solid #000; padding: 4px 6px; flex: none; }
        .msg { flex: 1; } .msg b { font-weight: 700; } ul { margin: 4px 0 0; padding-left: 18px; font-size: 12px; color: #333; }
        button { font: 600 12px system-ui, sans-serif; border: 1px solid #000; background: #fff; color: #000; padding: 5px 9px; cursor: pointer; }
        button.primary { background: #000; color: #fff; }
        .row { display: flex; gap: 8px; flex: none; }
      </style>
      <div class="bar" role="alert">
        <span class="tag">${verdict.level === "block" ? "LISTED" : "WARNING"}</span>
        <div class="msg"><b></b><ul></ul><div style="font-size:11px;margin-top:4px;color:#555">ThreatFusion checked this on your computer. It is a warning, not proof.</div></div>
        <div class="row"><button class="primary" data-act="leave">Go back</button><button data-act="report">Report a mistake</button><button data-act="dismiss">Dismiss</button></div>
      </div>`;
    root.querySelector("b").textContent = headline(verdict);
    const ul = root.querySelector("ul");
    reasons.forEach((r) => { const li = document.createElement("li"); li.textContent = r; ul.appendChild(li); });
    root.addEventListener("click", (e) => {
      const act = e.target && e.target.getAttribute && e.target.getAttribute("data-act");
      if (act === "leave") history.length > 1 ? history.back() : (location.href = "about:blank");
      if (act === "dismiss") { chrome.runtime.sendMessage({ type: "dismiss", host }); holder.remove(); }
      if (act === "report") {
        chrome.runtime.sendMessage({ type: "report", label: "false_positive" }, (r) => {
          e.target.textContent = r && r.ok ? "Reported — thank you" : "Could not report";
          e.target.disabled = true;
        });
      }
    });
    document.documentElement.appendChild(holder);
  }

  function flagPasswordFields() {
    const fields = document.querySelectorAll('input[type="password"]');
    fields.forEach((f) => {
      if (f.dataset.tfFlagged) return;
      f.dataset.tfFlagged = "1";
      f.style.outline = "3px solid #000";
      f.style.outlineOffset = "2px";
      f.title = "ThreatFusion: this site was flagged. Do not enter a password unless you are sure it is the real site.";
    });
    return fields.length;
  }

  function ask(attempt) {
    chrome.runtime.sendMessage({ type: "getVerdict" }, (reply) => {
      if (chrome.runtime.lastError || !reply) return;
      if (!reply.show) {
        if (reply.pending && attempt < 6) setTimeout(() => ask(attempt + 1), 600); // the check is still running
        return;
      }
      banner(reply.verdict, reply.host);
      flagPasswordFields();
      // single-page apps add the login form later: watch briefly, then stop
      const obs = new MutationObserver(() => flagPasswordFields());
      obs.observe(document.documentElement, { childList: true, subtree: true });
      setTimeout(() => obs.disconnect(), 15000);
    });
  }
  ask(0);
})();
