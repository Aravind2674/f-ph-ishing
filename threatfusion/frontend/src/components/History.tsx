import React, { useEffect, useState } from 'react';
import { fetchHistory } from '../api';
import type { ScanHistoryItem } from '../api';

export const History: React.FC = () => {
  const [history, setHistory] = useState<ScanHistoryItem[]>([]);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    fetchHistory()
      .then(setHistory)
      .catch(console.error)
      .finally(() => setLoading(false));
  }, []);

  if (loading) {
    return <div className="text-on-surface-variant p-md">Loading dashboard data...</div>;
  }

  const highRiskCount = history.filter(h => h.ml_label === 'Critical' || h.ml_label === 'High').length;
  const uniqueAssets = new Set(history.map(h => h.target)).size;

  return (
    <div className="space-y-xl animate-fade-in-up">
      {/* Hero Section */}
      <section>
        <h2 className="font-headline-lg text-headline-lg text-on-surface mb-lg">Security Intelligence Overview</h2>
        
        <div className="grid grid-cols-1 md:grid-cols-3 gap-md">
          {/* Stat Card 1 */}
          <div className="bg-surface-container-lowest border border-outline-variant rounded-lg p-lg flex flex-col justify-between hover:shadow-ambient transition-shadow">
            <div className="flex justify-between items-start mb-sm">
              <span className="font-label-md text-label-md text-on-surface-variant">Total Scans</span>
              <span className="material-symbols-outlined text-primary">radar</span>
            </div>
            <div className="font-display-lg text-display-lg text-on-surface">{history.length}</div>
            <div className="font-body-md text-body-md text-on-surface-variant mt-xs flex items-center">
              <span className="material-symbols-outlined text-[16px] text-[#16a34a] mr-1">trending_up</span>
              Live telemetry active
            </div>
          </div>
          
          {/* Stat Card 2 */}
          <div className="bg-surface-container-lowest border border-outline-variant rounded-lg p-lg flex flex-col justify-between hover:shadow-ambient transition-shadow">
            <div className="flex justify-between items-start mb-sm">
              <span className="font-label-md text-label-md text-on-surface-variant">High Risk Threats</span>
              <span className="material-symbols-outlined text-error">warning</span>
            </div>
            <div className="font-display-lg text-display-lg text-error">{highRiskCount}</div>
            <div className="font-body-md text-body-md text-on-surface-variant mt-xs flex items-center">
              Requires immediate review
            </div>
          </div>
          
          {/* Stat Card 3 */}
          <div className="bg-surface-container-lowest border border-outline-variant rounded-lg p-lg flex flex-col justify-between hover:shadow-ambient transition-shadow">
            <div className="flex justify-between items-start mb-sm">
              <span className="font-label-md text-label-md text-on-surface-variant">Scanned Assets</span>
              <span className="material-symbols-outlined text-primary">devices</span>
            </div>
            <div className="font-display-lg text-display-lg text-on-surface">{uniqueAssets}</div>
            <div className="font-body-md text-body-md text-on-surface-variant mt-xs flex items-center">
              <span className="material-symbols-outlined text-[16px] text-outline mr-1">trending_flat</span>
              Unique targets analyzed
            </div>
          </div>
        </div>
      </section>

      {/* Main Grid */}
      <section className="grid grid-cols-1 lg:grid-cols-3 gap-md">
        {/* Recent Scan Activity Table (Spans 2 columns) */}
        <div className="lg:col-span-2 bg-surface-container-lowest border border-outline-variant rounded-lg p-lg hover:shadow-ambient transition-shadow flex flex-col">
          <h3 className="font-title-lg text-title-lg text-on-surface mb-sm">Recent Scan Activity</h3>
          <div className="w-full h-[1px] bg-outline-variant mb-md"></div>
          
          <div className="overflow-x-auto flex-1">
            {history.length === 0 ? (
              <div className="text-on-surface-variant text-center py-xl">No scans recorded yet.</div>
            ) : (
              <table className="w-full text-left border-collapse">
                <thead>
                  <tr className="bg-surface-container-low font-label-md text-label-md text-on-surface-variant border-b border-outline-variant">
                    <th className="py-sm px-sm font-medium">Target</th>
                    <th className="py-sm px-sm font-medium">Date</th>
                    <th className="py-sm px-sm font-medium text-right">Baseline Score</th>
                    <th className="py-sm px-sm font-medium text-right">ML Score</th>
                    <th className="py-sm px-sm font-medium">Status</th>
                  </tr>
                </thead>
                <tbody className="font-mono-data text-mono-data text-on-surface">
                  {history.slice(0, 8).map((item) => (
                    <tr key={item.scan_id} className="border-b border-surface-variant hover:bg-surface-bright transition-colors">
                      <td className="py-sm px-sm">{item.target}</td>
                      <td className="py-sm px-sm text-on-surface-variant">{new Date(item.timestamp).toLocaleString()}</td>
                      <td className="py-sm px-sm text-right">{Math.round(item.baseline_score * 100)}</td>
                      <td className="py-sm px-sm text-right">{Math.round(item.ml_score * 100)}</td>
                      <td className="py-sm px-sm">
                        {item.ml_label === 'Critical' ? (
                          <span className="inline-flex items-center px-2 py-1 rounded-full bg-error-container text-on-error-container font-label-md text-[10px]">Critical</span>
                        ) : item.ml_label === 'High' ? (
                          <span className="inline-flex items-center px-2 py-1 rounded-full bg-[#fef08a] text-[#854d0e] font-label-md text-[10px]">High</span>
                        ) : item.ml_label === 'Medium' ? (
                          <span className="inline-flex items-center px-2 py-1 rounded-full bg-[#fef08a] text-[#854d0e] font-label-md text-[10px]">Investigate</span>
                        ) : (
                          <span className="inline-flex items-center px-2 py-1 rounded-full bg-[#dcfce7] text-[#166534] font-label-md text-[10px]">Secure</span>
                        )}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            )}
          </div>
        </div>

        {/* Threat Distribution Chart Summary */}
        <div className="bg-surface-container-lowest border border-outline-variant rounded-lg p-lg hover:shadow-ambient transition-shadow flex flex-col items-center justify-center relative overflow-hidden">
          <h3 className="font-title-lg text-title-lg text-on-surface absolute top-lg left-lg">Threat Distribution</h3>
          
          <div className="relative w-48 h-48 mt-xl">
            {/* High Risk (Red) */}
            <div className="absolute inset-0 rounded-full border-[12px] border-error" style={{ clipPath: 'polygon(50% 50%, 100% 0, 100% 100%, 80% 100%)', transform: 'rotate(-45deg)' }}></div>
            {/* Medium Risk (Yellow) */}
            <div className="absolute inset-0 rounded-full border-[12px] border-[#eab308]" style={{ clipPath: 'polygon(50% 50%, 80% 100%, 0 100%, 0 70%)', transform: 'rotate(-45deg)' }}></div>
            {/* Low Risk (Green) */}
            <div className="absolute inset-0 rounded-full border-[12px] border-[#22c55e]" style={{ clipPath: 'polygon(50% 50%, 0 70%, 0 0, 100% 0)', transform: 'rotate(-45deg)' }}></div>
            
            {/* Inner Circle for Donut effect */}
            <div className="absolute inset-4 rounded-full bg-surface-container-lowest flex items-center justify-center flex-col">
              <span className="font-display-lg text-display-lg text-on-surface">{history.length}</span>
              <span className="font-label-md text-label-md text-on-surface-variant">Total Scans</span>
            </div>
          </div>
          
          <div className="flex space-x-md mt-lg font-label-md text-label-md">
            <div className="flex items-center"><div className="w-3 h-3 rounded-full bg-error mr-2"></div>Critical/High</div>
            <div className="flex items-center"><div className="w-3 h-3 rounded-full bg-[#eab308] mr-2"></div>Med</div>
            <div className="flex items-center"><div className="w-3 h-3 rounded-full bg-[#22c55e] mr-2"></div>Low</div>
          </div>
        </div>
      </section>
    </div>
  );
};
