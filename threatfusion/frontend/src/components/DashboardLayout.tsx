import React from 'react';

interface DashboardLayoutProps {
  children: React.ReactNode;
  activeTab?: 'scan' | 'history' | 'settings';
  onTabChange?: (tab: 'scan' | 'history' | 'settings') => void;
}

export const DashboardLayout: React.FC<DashboardLayoutProps> = ({ children, activeTab = 'scan', onTabChange }) => {
  return (
    <div className="bg-background text-on-background font-body-md min-h-screen overflow-x-hidden selection:bg-primary-container selection:text-on-primary-container">
      {/* TopNavBar Shell */}
      <nav className="fixed top-0 right-0 w-full md:w-[calc(100%-16rem)] h-16 border-b border-white/10 z-40 bg-surface/80 dark:bg-surface/80 backdrop-blur-md flex justify-between items-center px-container-margin transition-all">
        <div className="flex items-center gap-4">
          <span className="material-symbols-outlined hidden md:block text-outline cursor-pointer hover:text-primary transition-colors">menu</span>
          <div className="flex items-center gap-2 text-on-surface-variant font-label-sm uppercase tracking-wider">
            <span className="hover:text-primary cursor-pointer transition-colors">ThreatFusion</span>
            <span className="material-symbols-outlined text-[16px]">chevron_right</span>
            <span className="text-primary font-bold border-b-2 border-primary pb-1 capitalize">{activeTab}</span>
          </div>
        </div>
        
        <div className="flex items-center gap-4">
          <div className="relative hidden lg:flex items-center group">
            <span className="material-symbols-outlined absolute left-3 text-outline group-focus-within:text-primary transition-colors">search</span>
            <input 
              type="text" 
              placeholder="Global search..." 
              className="bg-surface-container-high border border-white/10 rounded px-10 py-1.5 text-body-sm text-on-surface focus:outline-none focus:border-primary focus:ring-1 focus:ring-primary w-64 transition-all" 
            />
            <div className="absolute right-2 flex gap-1">
              <kbd className="bg-surface-variant text-outline px-1.5 rounded font-mono-data text-[10px]">⌘K</kbd>
            </div>
          </div>
          
          <button className="text-primary hover:text-primary-fixed-dim transition-colors font-label-sm uppercase tracking-wider hidden md:block">
            Export CSV
          </button>
          <button 
            onClick={() => onTabChange?.('scan')}
            className="bg-primary text-on-primary px-4 py-1.5 rounded font-label-sm uppercase tracking-wider hover:bg-primary-fixed-dim transition-colors hidden md:block">
            Quick Scan
          </button>
          
          <div className="w-px h-6 bg-white/10 mx-2 hidden md:block"></div>
          
          <button className="text-outline hover:text-primary transition-colors relative">
            <span className="material-symbols-outlined">notifications</span>
            <span className="absolute top-0 right-0 w-2 h-2 bg-error rounded-full animate-pulse"></span>
          </button>
          
          <button className="text-outline hover:text-primary transition-colors hidden sm:block">
            <span className="material-symbols-outlined">help</span>
          </button>
          
          <div className="w-8 h-8 rounded-full bg-surface-container-highest border border-white/10 overflow-hidden cursor-pointer hover:border-primary transition-colors">
            <img 
              src="https://lh3.googleusercontent.com/aida-public/AB6AXuCb20Z8HAVSNXfrywUnSuxMc4GCs4tTcjK8GIhsjBhKBme7o36y1vBT0Q0CNN_5uetYnDm4VY3Tc9FU4lPLsoiIb_uCz3NyHVkN_mTzqmSygSQxahwVBqHLUvWnPn1T-g2il5NNsxXSJKL6IZTWxk21ktMGtzHc6wdT3YeUqCG2CaRC03MD7D29pi-QvlASP2UqjNrnaQTlrD9p7ssUuHyBlt7cZrVrx6sUcDjsCSVJurBeV-8hhNmzPlxTYWX1zr9cjxEm-sDvuAEp" 
              alt="User profile"
              className="w-full h-full object-cover"
            />
          </div>
        </div>
      </nav>

      {/* SideNavBar Shell */}
      <aside className="h-screen w-64 fixed left-0 top-0 border-r border-white/10 backdrop-blur-xl bg-surface-container dark:bg-surface-container-low/70 flex flex-col py-container-margin z-50 hidden md:flex">
        <div className="px-6 mb-8 flex items-center gap-3">
          <div className="w-10 h-10 rounded bg-primary-container flex items-center justify-center text-on-primary-container shadow-[0_0_15px_rgba(77,142,255,0.3)]">
            <span className="material-symbols-outlined font-bold">radar</span>
          </div>
          <div>
            <h1 className="font-headline-md text-headline-md font-bold text-primary tracking-tighter">ThreatFusion</h1>
            <p className="font-label-sm text-label-sm text-tertiary-fixed-dim mt-0.5 animate-pulse flex items-center gap-1">
              <span className="w-1.5 h-1.5 bg-tertiary-fixed-dim rounded-full"></span> Live Monitoring
            </p>
          </div>
        </div>
        
        <nav className="flex-1 flex flex-col gap-1 px-2">
          <button 
            onClick={() => onTabChange?.('scan')}
            className={`flex items-center gap-3 px-4 py-3 rounded transition-colors group ${activeTab === 'scan' ? 'text-primary bg-primary/10 border-r-2 border-primary shadow-sm' : 'text-on-surface-variant hover:text-on-surface hover:bg-white/5 active:scale-95'}`}
          >
            <span className="material-symbols-outlined group-hover:text-primary transition-colors">radar</span>
            <span className={`font-label-md text-label-md ${activeTab === 'scan' ? 'font-bold' : ''}`}>Detailed Scan</span>
          </button>
          
          <button 
            onClick={() => onTabChange?.('history')}
            className={`flex items-center gap-3 px-4 py-3 rounded transition-colors group ${activeTab === 'history' ? 'text-primary bg-primary/10 border-r-2 border-primary shadow-sm' : 'text-on-surface-variant hover:text-on-surface hover:bg-white/5 active:scale-95'}`}
          >
            <span className="material-symbols-outlined group-hover:text-primary transition-colors">history</span>
            <span className={`font-label-md text-label-md ${activeTab === 'history' ? 'font-bold' : ''}`}>Scan History</span>
          </button>
          
          <button 
            onClick={() => onTabChange?.('settings')}
            className={`flex items-center gap-3 px-4 py-3 rounded transition-colors group ${activeTab === 'settings' ? 'text-primary bg-primary/10 border-r-2 border-primary shadow-sm' : 'text-on-surface-variant hover:text-on-surface hover:bg-white/5 active:scale-95'}`}
          >
            <span className="material-symbols-outlined group-hover:text-primary transition-colors">settings</span>
            <span className={`font-label-md text-label-md ${activeTab === 'settings' ? 'font-bold' : ''}`}>Settings</span>
          </button>
        </nav>
        
        <div className="px-4 mt-auto">
          <button 
            onClick={() => onTabChange?.('scan')}
            className="w-full bg-surface-variant text-on-surface border border-white/10 py-2 rounded font-label-md hover:bg-white/5 transition-all mb-4 flex items-center justify-center gap-2">
            <span className="material-symbols-outlined text-[18px]">add</span> Quick Scan
          </button>
          <div className="flex items-center gap-3 px-2 py-2 text-outline text-sm">
            <span className="material-symbols-outlined text-primary">lens</span>
            <span className="font-label-sm text-label-sm uppercase tracking-wider">System Status</span>
          </div>
        </div>
      </aside>

      {/* Main Workspace */}
      <main className="md:ml-64 pt-20 px-container-margin pb-container-margin min-h-screen">
        {children}
      </main>
    </div>
  );
};
