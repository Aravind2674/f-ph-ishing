document.addEventListener('DOMContentLoaded', async () => {
  const urlText = document.getElementById('target-url');
  const scanBtn = document.getElementById('scan-btn');
  const btnText = document.getElementById('btn-text');
  const btnLoader = document.getElementById('btn-loader');
  const errorBox = document.getElementById('error-box');
  const resultBox = document.getElementById('result-box');
  const modeBadge = document.getElementById('mode-badge');

  // Result elements
  const riskLabel = document.getElementById('risk-label');
  const riskMeter = document.getElementById('risk-meter');
  const mlScore = document.getElementById('ml-score');
  const baselineScore = document.getElementById('baseline-score');
  const avDetects = document.getElementById('av-detects');
  const openPorts = document.getElementById('open-ports');

  let targetUrl = '';

  // ── Monochrome severity mapping ─────────────────────────────────────────
  // Mirrors the dashboard's lib/severity: risk is encoded via bar density and
  // label text only — never colour.
  function severity(score01) {
    if (score01 >= 0.8) return { label: 'CRITICAL', bars: 5, weight: 700 };
    if (score01 >= 0.6) return { label: 'HIGH', bars: 4, weight: 600 };
    if (score01 >= 0.4) return { label: 'MEDIUM', bars: 3, weight: 500 };
    if (score01 >= 0.2) return { label: 'LOW', bars: 2, weight: 400 };
    return { label: 'MINIMAL', bars: 1, weight: 400 };
  }

  function paintMeter(bars) {
    const segs = riskMeter.querySelectorAll('span');
    segs.forEach((s, i) => s.classList.toggle('on', i < bars));
  }

  // ── Mode badge (best-effort) ────────────────────────────────────────────
  fetch('http://127.0.0.1:8000/health')
    .then((r) => r.json())
    .then((h) => {
      modeBadge.classList.add(h.mock_mode ? 'mock' : 'live');
      modeBadge.innerHTML =
        '<span class="dot"></span>' + (h.mock_mode ? 'Mock' : 'Live');
    })
    .catch(() => {
      modeBadge.textContent = 'Offline';
    });

  // ── Resolve the active tab's URL ────────────────────────────────────────
  chrome.tabs.query({ active: true, currentWindow: true }, (tabs) => {
    if (tabs.length > 0 && tabs[0].url) {
      targetUrl = tabs[0].url;
      try {
        urlText.textContent = new URL(targetUrl).hostname;
      } catch {
        urlText.textContent = targetUrl;
      }
      scanBtn.disabled = false;
    } else {
      urlText.textContent = 'Could not determine URL';
    }
  });

  // ── Scan (fetch logic unchanged) ────────────────────────────────────────
  scanBtn.addEventListener('click', async () => {
    if (!targetUrl) return;

    scanBtn.disabled = true;
    btnText.textContent = 'Scanning…';
    btnLoader.classList.remove('hidden');
    errorBox.classList.add('hidden');
    resultBox.classList.add('hidden');

    try {
      const response = await fetch('http://127.0.0.1:8000/scan', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ target: targetUrl, target_type: 'url' })
      });

      const data = await response.json();

      if (!response.ok || !data.success) {
        throw new Error(data.error || `Server error: ${response.status}`);
      }

      const res = data.result;
      // A null score means "no evidence" (provider outage / model unavailable). Never show it as 0
      // or "MINIMAL": that would read as a clean target.
      // Headline = transparent baseline score. The XGBoost score is experimental (VirusTotal-only
      // model) and is shown as the secondary stat.
      const hasScore = res.baseline_score !== null && res.baseline_score !== undefined;
      const score01 = hasScore ? res.baseline_score : 0;
      const sev = hasScore
        ? severity(score01)
        : { label: 'UNKNOWN', bars: 0, weight: 400 };

      mlScore.textContent = hasScore ? Math.round(score01 * 100) : '—';
      riskLabel.textContent = sev.label;
      riskLabel.style.fontWeight = String(sev.weight);
      riskLabel.style.color =
        hasScore && score01 >= 0.6 ? 'var(--foreground)' : 'var(--muted)';
      paintMeter(sev.bars);

      // (element id kept as 'baseline-score'; it now shows the experimental ML score)
      baselineScore.textContent =
        res.ml_score === null || res.ml_score === undefined
          ? '—'
          : Math.round(res.ml_score * 100);

      avDetects.textContent = res.virustotal
        ? `${res.virustotal.malicious_count}/${res.virustotal.total_engines}`
        : 'N/A';

      openPorts.textContent = res.shodan
        ? String(res.shodan.open_ports.length)
        : 'N/A';

      resultBox.classList.remove('hidden');
    } catch (err) {
      console.error(err);
      errorBox.textContent = err.message || 'Failed to connect to ThreatFusion API.';
      errorBox.classList.remove('hidden');
    } finally {
      scanBtn.disabled = false;
      btnText.textContent = 'Scan This Page';
      btnLoader.classList.add('hidden');
    }
  });
});
