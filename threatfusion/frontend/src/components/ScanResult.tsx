import React from 'react';
import type { ScanResult as IScanResult } from '../api';

interface ScanResultProps {
  result: IScanResult;
  onRescan?: () => void;
}

export const ScanResult: React.FC<ScanResultProps> = ({ result, onRescan }) => {
  const formatScore = (score: number) => Math.round(score * 100);
  const baselineScore = formatScore(result.baseline_score);
  const mlScore = formatScore(result.ml_score ?? result.baseline_score);

  const getGaugeColor = (score: number) => {
    if (score >= 80) return '#ba1a1a'; // Error / Critical
    if (score >= 50) return '#f59e0b'; // Amber / Warning
    return '#16a34a'; // Green / Secure
  };

  const getLabelClass = (label: string) => {
    switch (label) {
      case 'Critical': return 'bg-error-container text-on-error-container';
      case 'High': return 'bg-[#fef08a] text-[#854d0e]';
      case 'Medium': return 'bg-[#fef08a] text-[#854d0e]';
      case 'Low': return 'bg-[#dcfce7] text-[#166534]';
      default: return 'bg-surface-variant text-on-surface';
    }
  };

  const topExplanations = [...result.explanations]
    .sort((a, b) => Math.abs(b.shap_value) - Math.abs(a.shap_value))
    .slice(0, 5);
  
  const maxShap = Math.max(...topExplanations.map(e => Math.abs(e.shap_value)), 1);

  const handleExport = () => {
    const blob = new Blob([JSON.stringify(result, null, 2)], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `threatfusion-report-${result.scan_id}.json`;
    a.click();
    URL.revokeObjectURL(url);
  };

  return (
    <div className="animate-fade-in-up">
      {/* Target Header */}
      <div className="mb-xl flex flex-col md:flex-row justify-between items-start md:items-end gap-md">
        <div>
          <div className="flex items-center gap-sm mb-xs">
            <span className={`px-sm py-1 rounded-full font-label-md text-label-md uppercase ${getLabelClass(result.ml_label || 'Low')}`}>
              {result.ml_label || 'Unknown'}
            </span>
            <span className="font-mono-data text-mono-data text-on-surface-variant bg-surface-container-low px-sm py-1 rounded">
              Last Scanned: {new Date(result.timestamp).toLocaleString()}
            </span>
          </div>
          <h2 className="font-headline-lg text-headline-lg text-on-surface flex items-center gap-sm">
            {result.target}
            <span className="material-symbols-outlined text-outline-variant cursor-pointer hover:text-primary transition-colors text-[24px]">content_copy</span>
          </h2>
          <p className="font-mono-data text-mono-data text-secondary mt-xs">Type: {result.target_type}</p>
        </div>
        <div className="flex gap-sm">
          <button 
            onClick={onRescan}
            className="px-md py-xs rounded-lg border border-primary text-primary font-label-md text-label-md hover:bg-primary/5 transition-colors bg-surface-container-lowest"
          >
            Re-Scan
          </button>
          <button 
            onClick={handleExport}
            className="px-md py-xs rounded-lg bg-primary text-on-primary font-label-md text-label-md hover:bg-primary/90 transition-colors shadow-sm"
          >
            Export Report
          </button>
        </div>
      </div>

      {/* Dashboard Grid */}
      <div className="grid grid-cols-1 @4xl:grid-cols-12 gap-lg mb-xl">
        
        {/* Score Section */}
        <div className="@4xl:col-span-12 @6xl:col-span-8 bg-surface-container-lowest border border-surface-variant rounded-xl p-lg flex flex-col md:flex-row items-center justify-around gap-lg hover:shadow-ambient transition-shadow">
          <div className="flex flex-col items-center gap-md">
            <h3 className="font-title-lg text-title-lg text-on-surface">Baseline Heuristic Score</h3>
            <div className="relative w-40 h-40 flex items-center justify-center">
              <svg className="w-full h-full transform -rotate-90" viewBox="0 0 100 100">
                <circle cx="50" cy="50" r="40" fill="transparent" stroke="#e0e3e5" strokeWidth="8"></circle>
                <circle cx="50" cy="50" r="40" fill="transparent" stroke={getGaugeColor(baselineScore)} strokeWidth="8" strokeDasharray="251.2" strokeDashoffset={251.2 - (251.2 * baselineScore / 100)}></circle>
              </svg>
              <div className="absolute inset-0 flex flex-col items-center justify-center">
                <span className="font-headline-lg text-headline-lg text-on-surface">{baselineScore}</span>
                <span className="font-label-md text-label-md text-on-surface-variant">/100</span>
              </div>
            </div>
          </div>
          
          <div className="hidden md:block w-px h-32 bg-outline-variant"></div>
          <div className="md:hidden h-px w-full bg-outline-variant"></div>
          
          <div className="flex flex-col items-center gap-md">
            <h3 className="font-title-lg text-title-lg text-on-surface">ML Fusion Model Score</h3>
            <div className="relative w-40 h-40 flex items-center justify-center">
              <svg className="w-full h-full transform -rotate-90" viewBox="0 0 100 100">
                <circle cx="50" cy="50" r="40" fill="transparent" stroke="#e0e3e5" strokeWidth="8"></circle>
                <circle cx="50" cy="50" r="40" fill="transparent" stroke={getGaugeColor(mlScore)} strokeWidth="8" strokeDasharray="251.2" strokeDashoffset={251.2 - (251.2 * mlScore / 100)}></circle>
              </svg>
              <div className="absolute inset-0 flex flex-col items-center justify-center">
                <span className="font-headline-lg text-headline-lg text-on-surface">{mlScore}</span>
                <span className="font-label-md text-label-md text-on-surface-variant">/100</span>
              </div>
            </div>
          </div>
        </div>

        {/* ML Explanation Section */}
        <div className="@4xl:col-span-12 @6xl:col-span-4 bg-surface-container-lowest border border-surface-variant rounded-xl p-lg flex flex-col hover:shadow-ambient transition-shadow">
          <h3 className="font-title-lg text-title-lg text-on-surface mb-xs flex items-center gap-sm">
            <span className="material-symbols-outlined text-primary">psychology</span>
            AI Decision Rationale (SHAP)
          </h3>
          <hr className="border-outline-variant mb-md"/>
          <div className="flex flex-col gap-md flex-1 justify-center">
            {topExplanations.map((exp, idx) => {
              const widthPct = Math.max((Math.abs(exp.shap_value) / maxShap) * 100, 5);
              const isPositive = exp.shap_value > 0;
              return (
                <div key={idx}>
                  <div className="flex justify-between font-label-md text-label-md mb-1">
                    <span className="text-on-surface-variant">{exp.human_readable}</span>
                    <span className={`${isPositive ? 'text-error' : 'text-primary'} font-bold`}>
                      {isPositive ? '+' : ''}{exp.shap_value.toFixed(2)}
                    </span>
                  </div>
                  <div className={`w-full bg-surface-container-high h-2 rounded-full overflow-hidden flex ${isPositive ? 'justify-start' : 'justify-end'}`}>
                    <div className={`${isPositive ? 'bg-error' : 'bg-primary'} h-full rounded-full transition-all duration-1000`} style={{ width: `${widthPct}%` }}></div>
                  </div>
                </div>
              );
            })}
            {topExplanations.length === 0 && (
              <div className="text-on-surface-variant font-body-md text-center">No SHAP explanations available.</div>
            )}
          </div>
        </div>

        {/* Intelligence Panels */}
        
        {/* VirusTotal Panel */}
        <div className="@4xl:col-span-12 @6xl:col-span-4 bg-surface-container-lowest border border-surface-variant rounded-xl p-md flex flex-col hover:shadow-ambient transition-shadow">
          <h4 className="font-title-lg text-title-lg text-on-surface mb-sm flex items-center gap-sm">
            <span className="material-symbols-outlined text-secondary">bug_report</span>
            Reputation Data
          </h4>
          <hr className="border-outline-variant mb-md"/>
          <div className="flex items-center justify-between mb-sm">
            <span className="font-label-md text-label-md text-on-surface-variant">Malicious Engines</span>
            <span className={`font-mono-data text-mono-data px-2 py-1 rounded ${result.virustotal?.malicious_count > 0 ? 'bg-error-container text-on-error-container' : 'bg-[#dcfce7] text-[#166534]'}`}>
              {result.virustotal?.malicious_count ?? 0} / {result.virustotal?.total_engines ?? 0}
            </span>
          </div>
          <div className="bg-surface p-sm rounded border border-outline-variant mt-auto">
            <p className="font-body-md text-body-md text-on-surface-variant">
              {result.summary || "No summary generated."}
            </p>
          </div>
        </div>

        {/* Shodan/Network Panel */}
        <div className="@4xl:col-span-12 @6xl:col-span-4 bg-surface-container-lowest border border-surface-variant rounded-xl p-md flex flex-col hover:shadow-ambient transition-shadow">
          <h4 className="font-title-lg text-title-lg text-on-surface mb-sm flex items-center gap-sm">
            <span className="material-symbols-outlined text-secondary">router</span>
            Network Topology
          </h4>
          <hr className="border-outline-variant mb-md"/>
          
          <div className="mb-sm">
            <span className="font-label-md text-label-md text-on-surface-variant block mb-xs">Open Ports</span>
            <div className="flex gap-xs flex-wrap">
              {result.shodan?.open_ports?.length ? (
                result.shodan.open_ports.map((port: number) => {
                  const highRiskPorts = [21, 22, 23, 139, 445, 3389];
                  const isHighRisk = highRiskPorts.includes(port);
                  return (
                    <span key={port} className={`font-mono-data text-mono-data px-2 py-1 rounded ${isHighRisk ? 'bg-error-container text-on-error-container border border-error/20' : 'bg-surface-variant text-on-surface'}`}>
                      {port}
                    </span>
                  );
                })
              ) : (
                <span className="text-on-surface-variant font-label-md">No open ports detected</span>
              )}
            </div>
          </div>
          
          <div className="mt-auto">
            <span className="font-label-md text-label-md text-on-surface-variant block mb-xs">Vulnerabilities</span>
            {result.cve?.cves?.length ? (
              <div className="max-h-24 overflow-y-auto">
                {result.cve.cves.map((v: any, i: number) => (
                  <span key={i} className="font-mono-data text-mono-data text-error block truncate" title={v.id}>
                    {v.id} {v.severity && `(${v.severity})`}
                  </span>
                ))}
              </div>
            ) : (
              <span className="font-mono-data text-mono-data text-on-surface-variant">None known</span>
            )}
          </div>
        </div>

        {/* Tech Stack Panel */}
        <div className="@4xl:col-span-12 @6xl:col-span-4 bg-surface-container-lowest border border-surface-variant rounded-xl p-md flex flex-col hover:shadow-ambient transition-shadow">
          <h4 className="font-title-lg text-title-lg text-on-surface mb-sm flex items-center gap-sm">
            <span className="material-symbols-outlined text-secondary">layers</span>
            Tech Stack
          </h4>
          <hr className="border-outline-variant mb-md"/>
          
          <ul className="flex flex-col gap-sm overflow-y-auto max-h-48">
            {result.tech_fingerprint?.technologies?.length ? (
              result.tech_fingerprint.technologies.map((tech: any, idx: number) => (
                <li key={idx} className="flex justify-between items-center pb-sm border-b border-surface-variant last:border-0">
                  <span className="font-body-md text-body-md text-on-surface">{tech.name}</span>
                  <span className={`font-mono-data text-mono-data ${tech.is_eol ? 'text-error bg-error/10 px-2 rounded' : 'text-secondary'}`}>
                    {tech.version || 'Unknown'} {tech.is_eol ? '(EOL)' : ''}
                  </span>
                </li>
              ))
            ) : (
              <li className="text-on-surface-variant font-body-md text-center mt-md">No technologies detected.</li>
            )}
          </ul>
        </div>
        
      </div>
    </div>
  );
};
