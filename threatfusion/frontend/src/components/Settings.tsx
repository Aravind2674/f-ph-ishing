import React from 'react';

export const Settings: React.FC = () => {
  return (
    <div className="flex flex-col gap-6 animate-fade-in-up max-w-4xl mx-auto w-full">
      <div className="flex justify-between items-end">
        <div>
          <h2 className="text-headline-xl font-headline-xl font-bold text-on-surface tracking-tighter">System Configurations</h2>
          <p className="text-body-lg text-outline mt-1">Manage API keys and intelligence feeds.</p>
        </div>
      </div>

      <div className="glass-panel rounded-xl p-6">
        <h3 className="text-title-lg font-bold text-on-surface mb-6 flex items-center gap-2">
          <span className="material-symbols-outlined text-primary">key</span> Integration Keys
        </h3>
        
        <div className="flex flex-col gap-6">
          <div>
            <label className="block text-label-sm font-label-sm text-outline uppercase tracking-widest mb-2">VirusTotal API Key</label>
            <div className="flex gap-4">
              <input type="password" value="****************************************" className="flex-1 bg-surface-container-high border border-white/10 rounded px-4 py-2 text-on-surface focus:outline-none focus:border-primary transition-colors" readOnly />
              <button className="bg-surface-variant text-on-surface border border-white/10 px-4 py-2 rounded hover:bg-white/5 transition-all">Update</button>
            </div>
          </div>
          
          <div>
            <label className="block text-label-sm font-label-sm text-outline uppercase tracking-widest mb-2">Shodan API Key</label>
            <div className="flex gap-4">
              <input type="password" value="********************************" className="flex-1 bg-surface-container-high border border-white/10 rounded px-4 py-2 text-on-surface focus:outline-none focus:border-primary transition-colors" readOnly />
              <button className="bg-surface-variant text-on-surface border border-white/10 px-4 py-2 rounded hover:bg-white/5 transition-all">Update</button>
            </div>
          </div>
          
          <div>
            <label className="block text-label-sm font-label-sm text-outline uppercase tracking-widest mb-2">ThreatFox API Key</label>
            <div className="flex gap-4">
              <input type="password" defaultValue="" placeholder="Enter key..." className="flex-1 bg-surface-container-high border border-error/50 rounded px-4 py-2 text-on-surface focus:outline-none focus:border-primary transition-colors" />
              <button className="bg-primary text-on-primary px-4 py-2 rounded hover:bg-primary-fixed-dim transition-all">Save</button>
            </div>
            <p className="text-error text-body-sm mt-1 flex items-center gap-1"><span className="material-symbols-outlined text-[14px]">warning</span> Missing required key</p>
          </div>
        </div>
      </div>
    </div>
  );
};
