import React from 'react';
import type { ScanResult as IScanResult } from '../api';

interface ScanResultProps {
  result: IScanResult;
  onRescan?: () => void;
}

const VulnerabilityOrbitMap: React.FC<{ cves: any[] }> = ({ cves }) => {
  if (!cves || cves.length === 0) {
    return (
      <div className="flex flex-col items-center justify-center h-48 rounded-lg border border-white/10 p-4">
        <span className="material-symbols-outlined text-outline-variant text-[48px] mb-2">shield</span>
        <span className="text-on-surface-variant font-label-md text-center">No vulnerabilities detected</span>
      </div>
    );
  }

  const cx = 120;
  const cy = 100;
  const r = 60;

  return (
    <div className="flex flex-col items-center justify-center p-2 relative">
      <svg width="240" height="200" className="w-full max-w-[240px] drop-shadow-[0_0_15px_rgba(173,198,255,0.1)]">
        {/* Lines from center to orbits */}
        {cves.map((_, i) => {
          const angle = (i * 2 * Math.PI) / cves.length;
          const x = cx + r * Math.cos(angle);
          const y = cy + r * Math.sin(angle);
          return (
            <line
              key={`line-${i}`}
              x1={cx}
              y1={cy}
              x2={x}
              y2={y}
              stroke="rgba(255,255,255,0.1)"
              strokeWidth="1.5"
              strokeDasharray="4 4"
            />
          );
        })}

        {/* Center Target Node */}
        <circle cx={cx} cy={cy} r="18" fill="currentColor" className="text-primary pulse-dot" style={{ filter: 'drop-shadow(0 0 8px rgba(173,198,255,0.5))' }} />
        <text
          x={cx}
          y={cy + 3}
          textAnchor="middle"
          fill="#0b0e15"
          fontSize="8"
          fontWeight="bold"
          className="pointer-events-none"
        >
          TARGET
        </text>

        {/* Orbit Nodes */}
        {cves.map((cve, i) => {
          const angle = (i * 2 * Math.PI) / cves.length;
          const x = cx + r * Math.cos(angle);
          const y = cy + r * Math.sin(angle);
          
          let colorClass = 'text-primary';
          const cvss = cve.cvss_v3_score ?? cve.cvss_score ?? 5.0;
          if (cve.severity === 'CRITICAL' || cvss >= 9.0) colorClass = 'text-error';
          else if (cve.severity === 'HIGH' || cvss >= 7.0) colorClass = 'text-tertiary';
          else if (cve.severity === 'MEDIUM' || cvss >= 4.0) colorClass = 'text-yellow-400';

          return (
            <g key={`node-${i}`} className="cursor-pointer group">
              <circle
                cx={x}
                cy={y}
                r="8"
                fill="currentColor"
                className={`${colorClass} transition-transform duration-300 group-hover:scale-125`}
              />
              <text
                x={x}
                y={y - 12}
                textAnchor="middle"
                fill="#e1e2ec"
                fontSize="7"
                fontWeight="bold"
                className="opacity-0 group-hover:opacity-100 transition-opacity pointer-events-none drop-shadow-md"
              >
                {cve.cve_id || cve.id}
              </text>
              <circle
                cx={x}
                cy={y}
                r="12"
                fill="transparent"
                stroke="currentColor"
                strokeWidth="1"
                className={`${colorClass} opacity-0 group-hover:opacity-100 transition-opacity`}
              />
              <title>{`${cve.cve_id || cve.id} (CVSS: ${cvss})`}</title>
            </g>
          );
        })}
      </svg>
      <div className="flex gap-2 justify-center flex-wrap mt-2 text-[10px] font-mono-data text-outline">
        <span className="flex items-center gap-1"><span className="w-2.5 h-2.5 rounded-full bg-error"></span> Critical</span>
        <span className="flex items-center gap-1"><span className="w-2.5 h-2.5 rounded-full bg-tertiary"></span> High</span>
        <span className="flex items-center gap-1"><span className="w-2.5 h-2.5 rounded-full bg-yellow-400"></span> Medium</span>
      </div>
    </div>
  );
};

const AttackPathGraph: React.FC<{ path: any }> = ({ path }) => {
  const steps = ["Internet Access", ...path.nodes.map((n: any) => n.cve_id), path.summary.split("achieve ")[1] || "Compromise"];
  const width = 640;
  const height = 90;
  const nodeWidth = 110;
  const nodeHeight = 36;
  const padding = 20;
  const spacing = (width - padding * 2 - nodeWidth) / (steps.length - 1);

  return (
    <div className="overflow-x-auto w-full py-2">
      <svg width={width} height={height} className="min-w-[640px] mx-auto">
        <defs>
          <marker id="arrow" viewBox="0 0 10 10" refX="5" refY="5" markerWidth="5" markerHeight="5" orient="auto-start-reverse">
            <path d="M 0 0 L 10 5 L 0 10 z" fill="#8c909f" />
          </marker>
        </defs>
        
        {/* Draw connectors */}
        {steps.slice(0, -1).map((_, i) => {
          const x1 = padding + i * spacing + nodeWidth;
          const y1 = height / 2;
          const x2 = padding + (i + 1) * spacing;
          const y2 = height / 2;
          return (
            <g key={`arrow-${i}`}>
              <line x1={x1} y1={y1} x2={x2 - 8} y2={y2} stroke="#8c909f" strokeWidth="1.5" markerEnd="url(#arrow)" strokeDasharray="2 2" className="animate-[dash_1s_linear_infinite]" />
              {i < path.nodes.length && (
                <text x={(x1 + x2) / 2} y={y1 - 6} textAnchor="middle" fill="#adc6ff" fontSize="8" fontWeight="bold">
                  Exploits
                </text>
              )}
            </g>
          );
        })}

        {/* Draw nodes */}
        {steps.map((step, i) => {
          const x = padding + i * spacing;
          const y = height / 2 - nodeHeight / 2;
          
          let isStart = i === 0;
          let isEnd = i === steps.length - 1;
          let isVuln = !isStart && !isEnd;
          
          let bgColor = "rgba(46, 48, 56, 0.8)";
          let strokeColor = "rgba(255,255,255,0.1)";
          let textColor = "#e1e2ec";
          
          if (isStart) {
            bgColor = "rgba(0, 90, 194, 0.2)";
            strokeColor = "#adc6ff";
            textColor = "#adc6ff";
          } else if (isEnd) {
            bgColor = "rgba(255, 180, 171, 0.1)";
            strokeColor = "#ffb4ab";
            textColor = "#ffb4ab";
          } else {
            bgColor = "rgba(223, 116, 18, 0.1)";
            strokeColor = "#df7412";
            textColor = "#df7412";
          }

          return (
            <g key={`node-${i}`} className="group cursor-pointer">
              <rect
                x={x}
                y={y}
                width={nodeWidth}
                height={nodeHeight}
                rx="6"
                fill={bgColor}
                stroke={strokeColor}
                strokeWidth="1.5"
                className="transition-all duration-300 group-hover:filter group-hover:drop-shadow-[0_0_8px_rgba(255,255,255,0.2)] backdrop-blur-sm"
              />
              <text
                x={x + nodeWidth / 2}
                y={y + nodeHeight / 2 + 3}
                textAnchor="middle"
                fill={textColor}
                fontSize="8"
                fontWeight="bold"
              >
                {step.length > 18 ? step.substring(0, 16) + "..." : step}
              </text>
              {isVuln && (
                <title>{path.nodes[i - 1].description}</title>
              )}
            </g>
          );
        })}
      </svg>
      <style>{`@keyframes dash { to { stroke-dashoffset: -4; } }`}</style>
    </div>
  );
};

export const ScanResult: React.FC<ScanResultProps> = ({ result, onRescan }) => {
  const formatScore = (score: number) => Math.round(score * 100);
  const baselineScore = formatScore(result.baseline_score);
  const mlScore = formatScore(result.ml_score ?? result.baseline_score);

  const getGaugeColor = (score: number) => {
    if (score >= 80) return '#ffb4ab'; // Error
    if (score >= 50) return '#ffb786'; // Tertiary
    return '#adc6ff'; // Primary
  };

  const getLabelClass = (label: string) => {
    switch (label) {
      case 'Critical': return 'bg-error/20 text-error border-error/50';
      case 'High': return 'bg-tertiary/20 text-tertiary border-tertiary/50';
      case 'Medium': return 'bg-yellow-400/20 text-yellow-400 border-yellow-400/50';
      case 'Low': return 'bg-primary/20 text-primary border-primary/50';
      default: return 'bg-surface-variant text-on-surface border-white/10';
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
    <div className="flex flex-col gap-6 animate-fade-in-up">
      {/* Target Header */}
      <div className="flex justify-between items-end mb-4">
        <div>
          <div className="flex items-center gap-3 mb-2">
            <span className={`px-3 py-1 rounded text-xs uppercase tracking-widest font-bold border ${getLabelClass(result.ml_label || 'Low')}`}>
              {result.ml_label || 'Unknown'}
            </span>
            <span className="font-mono-data text-outline text-body-sm">
              Scan ID: {result.scan_id.substring(0, 8).toUpperCase()}
            </span>
          </div>
          <h2 className="text-headline-xl font-headline-xl font-bold text-on-surface tracking-tighter flex items-center gap-3">
            {result.target}
            <span className="material-symbols-outlined text-outline cursor-pointer hover:text-primary transition-colors text-[24px]">content_copy</span>
          </h2>
          <p className="font-mono-data text-primary mt-1 flex items-center gap-2">
             <span className="w-1.5 h-1.5 rounded-full bg-primary animate-pulse"></span> Scan Completed: {new Date(result.timestamp).toLocaleString()}
          </p>
        </div>
        <div className="flex gap-3">
          <button 
            onClick={onRescan}
            className="bg-surface-container-high border border-white/10 hover:border-primary/50 text-on-surface px-4 py-2 rounded transition-all flex items-center gap-2 font-label-md uppercase tracking-wider"
          >
            <span className="material-symbols-outlined text-[18px]">refresh</span> Re-Scan
          </button>
          <button 
            onClick={handleExport}
            className="bg-primary hover:bg-primary-fixed-dim text-on-primary px-4 py-2 rounded transition-all flex items-center gap-2 font-label-md uppercase tracking-wider shadow-[0_0_15px_rgba(173,198,255,0.3)]"
          >
            <span className="material-symbols-outlined text-[18px]">download</span> Export PDF
          </button>
        </div>
      </div>

      <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
          <div className="glass-panel-hot rounded-xl p-6 relative overflow-hidden group flex items-center justify-between">
              <div className="absolute top-0 left-0 w-full h-full bg-gradient-to-r from-error/5 to-transparent"></div>
              <div>
                  <h3 className="text-title-lg font-headline-md font-bold text-error glow-text-error mb-1">Baseline Risk</h3>
                  <p className="text-outline text-body-sm max-w-[200px]">Heuristic scoring based on signature matches.</p>
              </div>
              <div className="relative w-24 h-24">
                <svg className="w-full h-full transform -rotate-90" viewBox="0 0 100 100">
                  <circle cx="50" cy="50" r="40" stroke="rgba(255,255,255,0.05)" strokeWidth="8" fill="none" />
                  <circle cx="50" cy="50" r="40" stroke="currentColor" className="text-error" strokeWidth="8" fill="none" strokeDasharray="251.2" strokeDashoffset={251.2 - (251.2 * baselineScore / 100)} strokeLinecap="round" style={{ filter: 'drop-shadow(0 0 4px rgba(255,180,171,0.5))' }} />
                </svg>
                <div className="absolute inset-0 flex items-center justify-center">
                  <span className="text-headline-md font-bold text-on-surface">{baselineScore}</span>
                </div>
              </div>
          </div>
          <div className="glass-panel rounded-xl p-6 relative overflow-hidden group flex items-center justify-between border-primary/30 shadow-[0_0_20px_rgba(173,198,255,0.1)]">
              <div className="absolute top-0 right-0 w-32 h-32 bg-primary/10 rounded-full blur-3xl -mr-10 -mt-10"></div>
              <div>
                  <h3 className="text-title-lg font-headline-md font-bold text-primary glow-text-primary mb-1">ML Fusion Engine</h3>
                  <p className="text-outline text-body-sm max-w-[200px]">AI-driven predictive scoring using XGBoost.</p>
              </div>
              <div className="relative w-24 h-24">
                <svg className="w-full h-full transform -rotate-90" viewBox="0 0 100 100">
                  <circle cx="50" cy="50" r="40" stroke="rgba(255,255,255,0.05)" strokeWidth="8" fill="none" />
                  <circle cx="50" cy="50" r="40" stroke="currentColor" className="text-primary" strokeWidth="8" fill="none" strokeDasharray="251.2" strokeDashoffset={251.2 - (251.2 * mlScore / 100)} strokeLinecap="round" style={{ filter: 'drop-shadow(0 0 6px rgba(173,198,255,0.6))' }} />
                </svg>
                <div className="absolute inset-0 flex items-center justify-center">
                  <span className="text-headline-md font-bold text-on-surface">{mlScore}</span>
                </div>
              </div>
          </div>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
          <div className="glass-panel rounded-xl p-6 lg:col-span-2 relative overflow-hidden">
             <div className="flex justify-between items-center mb-6">
                  <h3 className="text-title-lg font-headline-md font-bold text-on-surface flex items-center gap-2">
                      <span className="material-symbols-outlined text-primary">psychology</span>
                      AI Decision Rationale (SHAP)
                  </h3>
             </div>
             <div className="flex flex-col gap-4">
               {topExplanations.map((exp, idx) => {
                 const widthPct = Math.max((Math.abs(exp.shap_value) / maxShap) * 100, 5);
                 const isPositive = exp.shap_value > 0;
                 return (
                   <div key={idx} className="bg-surface-container-high/50 p-3 rounded border border-white/5">
                       <div className="flex justify-between font-label-md text-label-md mb-2">
                           <span className="text-on-surface-variant">{exp.human_readable}</span>
                           <span className={`${isPositive ? 'text-error' : 'text-primary'} font-mono-data`}>
                               {isPositive ? '+' : ''}{exp.shap_value.toFixed(2)}
                           </span>
                       </div>
                       <div className={`w-full bg-surface-container h-1.5 rounded-full overflow-hidden flex ${isPositive ? 'justify-start' : 'justify-end'}`}>
                           <div className={`${isPositive ? 'bg-error shadow-[0_0_10px_rgba(255,180,171,0.5)]' : 'bg-primary shadow-[0_0_10px_rgba(173,198,255,0.5)]'} h-full rounded-full transition-all duration-1000`} style={{ width: `${widthPct}%` }}></div>
                       </div>
                   </div>
                 );
               })}
             </div>
          </div>

          <div className="glass-panel rounded-xl p-6 flex flex-col gap-4">
             <h3 className="text-title-lg font-headline-md font-bold text-on-surface flex items-center gap-2 mb-2">
                  <span className="material-symbols-outlined text-tertiary">layers</span>
                  Tech Stack
             </h3>
             {result.tech_fingerprint?.technologies?.length ? (
               result.tech_fingerprint.technologies.map((tech: any, idx: number) => (
                 <div key={idx} className="flex items-center justify-between p-3 border border-white/10 rounded hover:bg-white/5 transition-colors group">
                     <div className="flex items-center gap-3">
                         <div className="w-8 h-8 rounded bg-surface-container flex items-center justify-center text-outline group-hover:text-primary transition-colors">
                             <span className="material-symbols-outlined text-[18px]">terminal</span>
                         </div>
                         <span className="text-body-sm text-on-surface">{tech.name}</span>
                     </div>
                     <span className={`text-xs font-mono-data px-2 py-1 rounded ${tech.is_eol ? 'bg-error/20 text-error border border-error/30' : 'bg-surface-variant text-outline border border-white/5'}`}>
                         v{tech.version || 'Unknown'} {tech.is_eol ? '(EOL)' : ''}
                     </span>
                 </div>
               ))
             ) : (
               <div className="text-outline text-body-sm p-4 text-center">No technologies detected.</div>
             )}
          </div>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6 mb-6">
          <div className="glass-panel rounded-xl p-6 flex flex-col gap-4">
             <h3 className="text-title-lg font-headline-md font-bold text-on-surface flex items-center gap-2 mb-4">
                  <span className="material-symbols-outlined text-tertiary">radar</span>
                  Network Exposure (Shodan)
             </h3>
             {result.shodan ? (
                 <div className="flex flex-col gap-5">
                     <div className="flex flex-col gap-2">
                         <span className="text-outline text-label-sm uppercase tracking-widest font-bold">Open Ports</span>
                         <div className="flex gap-2 flex-wrap">
                             {result.shodan.open_ports?.length ? result.shodan.open_ports.map((port: number) => (
                                 <span key={port} className="bg-surface-container hover:bg-surface-container-high transition-colors text-on-surface font-mono-data text-xs px-3 py-1.5 rounded border border-white/5 flex items-center gap-1"><span className="w-1.5 h-1.5 rounded-full bg-tertiary"></span>{port}</span>
                             )) : <span className="text-outline text-xs">None detected</span>}
                         </div>
                     </div>
                     <div className="flex flex-col gap-2">
                         <span className="text-outline text-label-sm uppercase tracking-widest font-bold">Hostnames</span>
                         <div className="flex gap-2 flex-wrap">
                             {result.shodan.hostnames?.length ? result.shodan.hostnames.map((hn: string) => (
                                 <span key={hn} className="bg-surface-container text-on-surface text-xs px-2 py-1 rounded border border-white/5">{hn}</span>
                             )) : <span className="text-outline text-xs">None detected</span>}
                         </div>
                     </div>
                     <div className="flex flex-col gap-2">
                         <span className="text-outline text-label-sm uppercase tracking-widest font-bold">CPEs Detected</span>
                         <div className="flex gap-2 flex-wrap">
                             {result.shodan.cpes?.length ? result.shodan.cpes.slice(0, 5).map((cpe: string) => (
                                 <span key={cpe} className="bg-surface-container text-outline text-[10px] font-mono-data px-2 py-1 rounded border border-white/5 break-all">{cpe}</span>
                             )) : <span className="text-outline text-xs">None detected</span>}
                             {result.shodan.cpes?.length > 5 && <span className="text-outline text-[10px] px-2 py-1">+{result.shodan.cpes.length - 5} more</span>}
                         </div>
                     </div>
                 </div>
             ) : (
                 <div className="text-outline text-body-sm p-4 text-center border border-white/5 rounded bg-surface-container-low/50 h-full flex flex-col items-center justify-center gap-2">
                     <span className="material-symbols-outlined text-[32px] opacity-50">cloud_off</span>
                     No Shodan data available for this target.
                 </div>
             )}
          </div>

          <div className="glass-panel rounded-xl p-6">
               <div className="flex justify-between items-center mb-6">
                    <h3 className="text-title-lg font-headline-md font-bold text-on-surface flex items-center gap-2">
                        <span className="material-symbols-outlined text-tertiary">hub</span>
                        Vulnerability Exposure Orbit Map
                    </h3>
               </div>
               <VulnerabilityOrbitMap cves={result.cve?.cves || []} />
          </div>
      </div>

      {result.attack_paths && result.attack_paths.length > 0 && (
        <div className="glass-panel rounded-xl p-6 border border-error/20 shadow-[0_0_30px_rgba(255,180,171,0.05)]">
             <div className="flex justify-between items-center mb-6">
                  <h3 className="text-title-lg font-headline-md font-bold text-error flex items-center gap-2">
                      <span className="material-symbols-outlined text-error">account_tree</span>
                      Predictive Attack Chains
                  </h3>
             </div>
             
             <div className="flex flex-col gap-6">
               {result.attack_paths.map((path) => (
                 <div key={path.path_id} className="border border-white/10 rounded-lg bg-surface-container-low/50 overflow-hidden">
                     <div className="flex justify-between items-center p-4 border-b border-white/10 bg-black/20">
                         <span className="font-label-md uppercase tracking-wider text-outline">Path #{path.path_id} <span className="text-on-surface mx-2">•</span> {path.summary}</span>
                         <span className="text-error font-mono-data text-xs bg-error/10 px-2 py-1 rounded border border-error/20 flex items-center gap-1">
                            <span className="material-symbols-outlined text-[14px]">warning</span> Probability: {Math.round(path.total_risk_score * 100)}%
                         </span>
                     </div>
                     <div className="p-4">
                         <AttackPathGraph path={path} />
                     </div>
                 </div>
               ))}
             </div>
        </div>
      )}
    </div>
  );
};
