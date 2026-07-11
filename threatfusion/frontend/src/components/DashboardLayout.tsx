import React from 'react';

interface DashboardLayoutProps {
  children: React.ReactNode;
  activeTab?: 'dashboard' | 'scan' | 'history';
  onTabChange?: (tab: 'dashboard' | 'scan' | 'history') => void;
}

export const DashboardLayout: React.FC<DashboardLayoutProps> = ({ children, activeTab = 'scan', onTabChange }) => {
  return (
    <div className="bg-background text-on-background font-body-md min-h-screen flex text-body-md overflow-x-hidden">
      {/* SideNavBar */}
      <nav className="hidden md:flex flex-col h-screen w-[280px] bg-surface border-r border-outline-variant py-lg px-md fixed left-0 top-0 z-50">
        <div className="mb-xl flex items-center gap-sm px-xs">
          <div className="w-8 h-8 rounded bg-primary flex items-center justify-center">
            <span className="material-symbols-outlined text-on-primary text-[20px]">security</span>
          </div>
          <div>
            <h1 className="font-headline-md text-headline-md font-bold text-primary">ThreatFusion</h1>
            <p className="font-label-md text-label-md text-on-surface-variant">AI Risk Intelligence</p>
          </div>
        </div>

        <ul className="flex flex-col gap-xs flex-grow">
          <li>
            <button 
              onClick={() => onTabChange?.('dashboard')}
              className={`w-full flex items-center gap-sm px-md py-sm rounded-lg transition-colors duration-150 ${activeTab === 'dashboard' ? 'text-primary font-bold border-l-4 border-primary bg-primary/5 opacity-80' : 'text-on-surface-variant hover:bg-surface-container-high'}`}
            >
              <span className="material-symbols-outlined">dashboard</span>
              <span className="font-label-md text-label-md">Dashboard</span>
            </button>
          </li>
          <li>
            <button 
              onClick={() => onTabChange?.('scan')}
              className={`w-full flex items-center gap-sm px-md py-sm rounded-lg transition-colors duration-150 ${activeTab === 'scan' ? 'text-primary font-bold border-l-4 border-primary bg-primary/5 opacity-80' : 'text-on-surface-variant hover:bg-surface-container-high'}`}
            >
              <span className="material-symbols-outlined">biotech</span>
              <span className="font-label-md text-label-md">Detailed Scan</span>
            </button>
          </li>
          <li>
            <button 
              onClick={() => onTabChange?.('history')}
              className={`w-full flex items-center gap-sm px-md py-sm rounded-lg transition-colors duration-150 ${activeTab === 'history' ? 'text-primary font-bold border-l-4 border-primary bg-primary/5 opacity-80' : 'text-on-surface-variant hover:bg-surface-container-high'}`}
            >
              <span className="material-symbols-outlined">history</span>
              <span className="font-label-md text-label-md">Scan History</span>
            </button>
          </li>
          <li>
            <button className="w-full flex items-center gap-sm px-md py-sm rounded-lg text-on-surface-variant hover:bg-surface-container-high transition-colors">
              <span className="material-symbols-outlined">settings</span>
              <span className="font-label-md text-label-md">Settings</span>
            </button>
          </li>
          <li className="mt-auto">
            <button className="w-full flex items-center gap-sm px-md py-sm rounded-lg text-on-surface-variant hover:bg-surface-container-high transition-colors">
              <span className="material-symbols-outlined">description</span>
              <span className="font-label-md text-label-md">Documentation</span>
            </button>
          </li>
        </ul>
      </nav>

      {/* Main Content Area */}
      <main className="flex-1 md:ml-[280px] flex flex-col min-h-screen relative pb-20">
        
        {/* TopNavBar */}
        <header className="flex justify-between items-center w-full h-16 px-gutter bg-surface-bright border-b border-outline-variant sticky top-0 z-40">
          <div className="flex items-center gap-md lg:hidden">
            <span className="material-symbols-outlined text-on-surface cursor-pointer">menu</span>
            <span className="font-headline-md text-headline-md font-bold text-on-surface">ThreatFusion</span>
          </div>
          
          <div className="hidden lg:flex items-center max-w-md w-full relative">
            <span className="material-symbols-outlined absolute left-sm text-outline">search</span>
            <input 
              type="text" 
              placeholder="Search domains, IPs, hashes..." 
              className="w-full bg-surface-container pl-[40px] pr-md py-xs rounded-full border border-outline-variant focus:ring-2 focus:ring-primary/10 focus:border-primary outline-none transition-all font-body-md text-body-md" 
            />
          </div>

          <div className="flex items-center gap-md">
            <button className="text-on-surface-variant hover:text-primary transition-colors focus:ring-2 focus:ring-primary/10 rounded-full p-xs">
              <span className="material-symbols-outlined">notifications</span>
            </button>
            <button className="text-on-surface-variant hover:text-primary transition-colors focus:ring-2 focus:ring-primary/10 rounded-full p-xs">
              <span className="material-symbols-outlined">dns</span>
            </button>
            <div className="w-8 h-8 rounded-full bg-primary flex items-center justify-center text-on-primary font-bold ml-sm cursor-pointer border border-outline-variant">
              <span>A</span>
            </div>
          </div>
        </header>

        {/* Canvas */}
        <div className="flex-1 p-md md:p-xl max-w-container-max mx-auto w-full @container">
          {children}
        </div>

      </main>
    </div>
  );
};
