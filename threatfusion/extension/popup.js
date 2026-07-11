document.addEventListener('DOMContentLoaded', async () => {
  const urlText = document.getElementById('target-url');
  const scanBtn = document.getElementById('scan-btn');
  const btnText = document.getElementById('btn-text');
  const btnLoader = document.getElementById('btn-loader');
  const errorBox = document.getElementById('error-box');
  const resultBox = document.getElementById('result-box');
  
  // Stats elements
  const riskLabel = document.getElementById('risk-label');
  const mlScore = document.getElementById('ml-score');
  const baselineScore = document.getElementById('baseline-score');
  const avDetects = document.getElementById('av-detects');
  const openPorts = document.getElementById('open-ports');

  let targetUrl = '';

  // Get current active tab
  chrome.tabs.query({ active: true, currentWindow: true }, (tabs) => {
    if (tabs.length > 0 && tabs[0].url) {
      targetUrl = tabs[0].url;
      // Truncate for display
      try {
        const urlObj = new URL(targetUrl);
        urlText.textContent = urlObj.hostname; // Display just the domain for cleanliness
      } catch {
        urlText.textContent = targetUrl;
      }
      scanBtn.disabled = false;
    } else {
      urlText.textContent = 'Could not determine URL';
    }
  });

  scanBtn.addEventListener('click', async () => {
    if (!targetUrl) return;

    // UI Loading state
    scanBtn.disabled = true;
    btnText.textContent = 'Scanning...';
    btnLoader.classList.remove('hidden');
    errorBox.classList.add('hidden');
    resultBox.classList.add('hidden');

    try {
      const response = await fetch('http://127.0.0.1:8000/scan', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json'
        },
        body: JSON.stringify({
          target: targetUrl,
          target_type: 'url'
        })
      });

      const data = await response.json();

      if (!response.ok || !data.success) {
        throw new Error(data.error || `Server error: ${response.status}`);
      }

      const res = data.result;
      
      // Update UI with results
      const scorePct = Math.round((res.ml_score || 0) * 100);
      mlScore.textContent = `${scorePct}%`;
      riskLabel.textContent = res.ml_label || 'Unknown';
      
      // Colors based on risk
      let color = 'var(--risk-low)';
      if (res.ml_label === 'Critical') color = 'var(--risk-critical)';
      else if (res.ml_label === 'High') color = 'var(--risk-high)';
      else if (res.ml_label === 'Medium') color = 'var(--risk-medium)';
      
      riskLabel.style.color = color;
      mlScore.style.color = color;
      
      baselineScore.textContent = `${Math.round((res.baseline_score || 0) * 100)}%`;
      
      if (res.virustotal) {
        avDetects.textContent = `${res.virustotal.malicious_count}/${res.virustotal.total_engines}`;
      } else {
        avDetects.textContent = 'N/A';
      }
      
      if (res.shodan) {
        openPorts.textContent = res.shodan.open_ports.length.toString();
      } else {
        openPorts.textContent = 'N/A';
      }
      
      resultBox.classList.remove('hidden');

    } catch (err) {
      console.error(err);
      errorBox.textContent = err.message || 'Failed to connect to ThreatFusion API.';
      errorBox.classList.remove('hidden');
    } finally {
      // Reset button
      scanBtn.disabled = false;
      btnText.textContent = 'Scan This Page';
      btnLoader.classList.add('hidden');
    }
  });
});
