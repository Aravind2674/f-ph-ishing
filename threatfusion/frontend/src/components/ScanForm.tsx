import React, { useState } from 'react';
import type { ScanRequest } from '../api';

interface ScanFormProps {
  onSubmit: (req: ScanRequest) => void;
  loading: boolean;
}

export const ScanForm: React.FC<ScanFormProps> = ({ onSubmit, loading }) => {
  const [target, setTarget] = useState('');
  const [type, setType] = useState<ScanRequest['target_type']>('domain');

  const handleSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    if (!target.trim()) return;
    onSubmit({ target, target_type: type });
  };

  return (
    <div className="bg-surface-container-lowest border border-outline-variant rounded-xl p-lg hover:shadow-ambient transition-shadow">
      <h2 className="font-title-lg text-title-lg text-on-surface mb-md flex items-center gap-sm">
        <span className="material-symbols-outlined text-primary">target</span>
        New Scan
      </h2>
      
      <form onSubmit={handleSubmit} className="flex flex-col sm:flex-row gap-md items-center">
        <div className="w-full sm:w-auto min-w-[150px]">
          <select 
            className="w-full bg-surface-container-low border border-outline-variant rounded-lg py-sm px-md text-on-surface focus:ring-2 focus:ring-primary/10 focus:border-primary outline-none transition-all font-body-md"
            value={type} 
            onChange={e => setType(e.target.value as any)}
            disabled={loading}
          >
            <option value="domain">Domain</option>
            <option value="ip">IP Address</option>
            <option value="url">URL</option>
            <option value="file_hash">File Hash</option>
          </select>
        </div>
        
        <div className="w-full flex-1 relative">
          <span className="material-symbols-outlined absolute left-sm top-1/2 -translate-y-1/2 text-outline">search</span>
          <input 
            type="text" 
            className="w-full bg-surface-container-low pl-[40px] pr-md py-sm rounded-lg border border-outline-variant focus:ring-2 focus:ring-primary/10 focus:border-primary outline-none transition-all font-body-md text-body-md text-on-surface" 
            placeholder="e.g. evil.example.com, 8.8.8.8..." 
            value={target}
            onChange={e => setTarget(e.target.value)}
            disabled={loading}
          />
        </div>
        
        <button 
          type="submit" 
          disabled={loading || !target.trim()}
          className="w-full sm:w-auto px-lg py-sm bg-primary text-on-primary font-label-md text-label-md rounded-lg hover:bg-primary/90 transition-colors flex items-center justify-center gap-sm disabled:opacity-70 disabled:cursor-not-allowed"
        >
          {loading ? (
            <span className="material-symbols-outlined animate-spin text-[20px]">progress_activity</span>
          ) : (
            <>
              <span className="material-symbols-outlined text-[20px]">radar</span>
              Scan Now
            </>
          )}
        </button>
      </form>
    </div>
  );
};
