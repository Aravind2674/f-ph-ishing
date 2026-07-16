import React, { useState, useEffect } from 'react';
import { fetchHistory } from '../api';
import type { ScanHistoryItem } from '../api';

export const History: React.FC = () => {
  const [history, setHistory] = useState<ScanHistoryItem[]>([]);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    loadHistory();
  }, []);

  const loadHistory = async () => {
    setLoading(true);
    try {
      const data = await fetchHistory();
      setHistory(data as any);
    } catch (err) {
      console.error('Failed to fetch history', err);
    } finally {
      setLoading(false);
    }
  };

  const getFinalScore = (s: ScanHistoryItem) => s.ml_score ?? s.baseline_score;

  const totalScans = history.length;
  const highRiskThreats = history.filter(s => getFinalScore(s) >= 0.5).length;
  const uniqueTargets = new Set(history.map(s => s.target)).size;

  const critical = history.filter(s => getFinalScore(s) >= 0.8).length;
  const high = history.filter(s => getFinalScore(s) >= 0.5 && getFinalScore(s) < 0.8).length;
  const med = history.filter(s => getFinalScore(s) >= 0.3 && getFinalScore(s) < 0.5).length;
  const low = history.filter(s => getFinalScore(s) < 0.3).length;

  const getStatusBadge = (score: number) => {
    if (score >= 0.8) {
      return <span className="bg-[#ffb4ab]/20 text-[#ffb4ab] border border-[#ffb4ab]/30 px-2 py-0.5 rounded text-[10px] font-bold inline-block w-[50px] text-center">Critical</span>;
    }
    if (score >= 0.5) {
      return <span className="bg-[#ffb786]/20 text-[#ffb786] border border-[#ffb786]/30 px-2 py-0.5 rounded text-[10px] font-bold inline-block w-[50px] text-center">High</span>;
    }
    return <span className="bg-[#b4f8c8]/20 text-[#b4f8c8] border border-[#b4f8c8]/30 px-2 py-0.5 rounded text-[10px] font-bold inline-block w-[50px] text-center">Secure</span>;
  };

  return (
    <div className="flex flex-col w-full h-full text-on-surface p-2 gap-4">
      <h2 className="text-[22px] font-bold tracking-wide">Security Intelligence Overview</h2>

      {/* Top KPIs Box */}
      <div className="grid grid-cols-1 md:grid-cols-3 border border-outline-variant/40 rounded-sm bg-[#15171e]">
        {/* KPI 1 */}
        <div className="p-3 border-b md:border-b-0 md:border-r border-outline-variant/40 flex flex-col relative">
          <div className="flex justify-between items-start mb-1">
            <span className="text-[11px] text-outline uppercase font-semibold">Total Scans</span>
            <span className="material-symbols-outlined text-outline-variant text-[16px]">radar</span>
          </div>
          <span className="text-[20px] font-bold leading-tight">{totalScans}</span>
          <div className="text-[11px] text-outline flex items-center gap-1 mt-1">
            <span className="material-symbols-outlined text-[#b4f8c8] text-[14px]">trending_up</span>
            Live telemetry active
          </div>
        </div>

        {/* KPI 2 */}
        <div className="p-3 border-b md:border-b-0 md:border-r border-outline-variant/40 flex flex-col relative">
          <div className="flex justify-between items-start mb-1">
            <span className="text-[11px] text-outline uppercase font-semibold">High Risk Threats</span>
            <span className="material-symbols-outlined text-outline-variant text-[16px]">warning</span>
          </div>
          <span className="text-[20px] font-bold leading-tight text-[#ffb4ab]">{highRiskThreats}</span>
          <div className="text-[11px] text-outline mt-1">
            Requires immediate review
          </div>
        </div>

        {/* KPI 3 */}
        <div className="p-3 flex flex-col relative">
          <div className="flex justify-between items-start mb-1">
            <span className="text-[11px] text-outline uppercase font-semibold">Scanned Assets</span>
            <span className="material-symbols-outlined text-outline-variant text-[16px]">devices</span>
          </div>
          <span className="text-[20px] font-bold leading-tight">{uniqueTargets}</span>
          <div className="text-[11px] text-outline mt-1 flex items-center gap-1">
             <span className="material-symbols-outlined text-outline text-[12px]">arrow_right_alt</span> Unique targets analyzed
          </div>
        </div>
      </div>

      {/* Main Content Area */}
      <div className="grid grid-cols-1 lg:grid-cols-[1fr_350px] border border-outline-variant/40 rounded-sm bg-[#15171e] min-h-[400px]">
        {/* Left: Table */}
        <div className="flex flex-col border-b lg:border-b-0 lg:border-r border-outline-variant/40">
          <div className="p-2 border-b border-outline-variant/40 bg-white/5">
            <h3 className="text-[13px] font-bold">Recent Scan Activity</h3>
          </div>
          <div className="overflow-x-auto">
            <table className="w-full text-left text-[12px]">
              <thead>
                <tr className="border-b border-outline-variant/40 text-outline">
                  <th className="p-2 font-semibold">Target</th>
                  <th className="p-2 font-semibold">Date</th>
                  <th className="p-2 font-semibold text-right">Baseline Score</th>
                  <th className="p-2 font-semibold text-right pr-6">ML Score Status</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-outline-variant/20">
                {loading ? (
                  <tr>
                    <td colSpan={4} className="p-8 text-center text-outline">Loading...</td>
                  </tr>
                ) : history.length === 0 ? (
                  <tr>
                    <td colSpan={4} className="p-8 text-center text-outline">No scans found.</td>
                  </tr>
                ) : (
                  history.map((scan) => (
                    <tr key={scan.scan_id} className="hover:bg-white/5 transition-colors">
                      <td className="p-2 font-mono-data">{scan.target}</td>
                      <td className="p-2 text-outline">{new Date(scan.timestamp || '').toLocaleString('en-GB', { day: '2-digit', month: '2-digit', year: 'numeric', hour: '2-digit', minute: '2-digit', second: '2-digit' })}</td>
                      <td className="p-2 text-right">{(scan.baseline_score * 100).toFixed(0)}</td>
                      <td className="p-2 text-right pr-4 flex items-center justify-end gap-2">
                        <span>{((scan.ml_score ?? scan.baseline_score) * 100).toFixed(0)}</span>
                        {getStatusBadge(getFinalScore(scan))}
                      </td>
                    </tr>
                  ))
                )}
              </tbody>
            </table>
          </div>
        </div>

        {/* Right: Chart */}
        <div className="p-6 flex flex-col items-center justify-center relative bg-surface-container-low/50">
           {/* Diamond Donut SVG */}
           <svg width="220" height="220" viewBox="0 0 200 200" className="overflow-visible">
              <defs>
                 <filter id="glow" x="-20%" y="-20%" width="140%" height="140%">
                   <feGaussianBlur stdDeviation="4" result="blur" />
                   <feComposite in="SourceGraphic" in2="blur" operator="over" />
                 </filter>
              </defs>
              
              <g transform="translate(100, 100) rotate(45)">
                 {/* Top Left (Green) */}
                 <path d="M -80 -80 L -30 -80 L -30 -30 L -80 -30 Z" fill="none" stroke="#22c55e" strokeWidth="8" strokeDasharray="140" strokeDashoffset={totalScans > 0 ? (low/totalScans < 0.25 ? 140 - (low/totalScans)*140 : 0) : 140} />
                 <line x1="-70" y1="-70" x2="-20" y2="-70" stroke="#22c55e" strokeWidth="12" strokeLinecap="round" />
                 <line x1="-70" y1="-70" x2="-70" y2="-20" stroke="#22c55e" strokeWidth="12" strokeLinecap="round" />
                 
                 {/* Top Right (Pink) */}
                 <line x1="70" y1="-70" x2="20" y2="-70" stroke="#ffb4ab" strokeWidth="12" strokeLinecap="round" />
                 <line x1="70" y1="-70" x2="70" y2="-20" stroke="#ffb4ab" strokeWidth="12" strokeLinecap="round" />
                 
                 {/* Bottom Right (Orange) */}
                 <line x1="70" y1="70" x2="20" y2="70" stroke="#ffb786" strokeWidth="12" strokeLinecap="round" />
                 <line x1="70" y1="70" x2="70" y2="20" stroke="#ffb786" strokeWidth="12" strokeLinecap="round" />
                 
                 {/* Bottom Left (Green) */}
                 <line x1="-70" y1="70" x2="-20" y2="70" stroke="#eab308" strokeWidth="12" strokeLinecap="round" />
                 <line x1="-70" y1="70" x2="-70" y2="20" stroke="#eab308" strokeWidth="12" strokeLinecap="round" />
              </g>
           </svg>
           
           <div className="absolute inset-0 flex flex-col items-center justify-center pointer-events-none pb-4">
              <span className="text-[24px] font-bold text-on-surface">{totalScans}</span>
              <span className="text-[11px] text-primary">Total Scans</span>
           </div>

           <div className="mt-8 flex gap-3 text-[11px] font-bold">
              <div className="flex items-center gap-1"><span className="w-2.5 h-2.5 rounded-full bg-[#ffb4ab]"></span> Critical</div>
              <div className="flex items-center gap-1"><span className="w-2.5 h-2.5 rounded-full bg-[#ffb786]"></span> High</div>
              <div className="flex items-center gap-1"><span className="w-2.5 h-2.5 rounded-full bg-[#eab308]"></span> Med</div>
              <div className="flex items-center gap-1"><span className="w-2.5 h-2.5 rounded-full bg-[#22c55e]"></span> Low</div>
           </div>
        </div>
      </div>
    </div>
  );
};
