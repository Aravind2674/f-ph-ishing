import { useState } from 'react';
import { DashboardLayout } from './components/DashboardLayout';
import { ScanForm } from './components/ScanForm';
import { ScanResult } from './components/ScanResult';
import { History } from './components/History';
import { Settings } from './components/Settings';
import { submitScan } from './api';
import type { ScanResult as IScanResult, ScanRequest } from './api';

function App() {
  const [currentView, setCurrentView] = useState<'scan' | 'history' | 'settings'>('scan');
  const [scanResult, setScanResult] = useState<IScanResult | null>(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const handleScanSubmit = async (request: ScanRequest) => {
    setLoading(true);
    setError(null);
    setScanResult(null);
    setCurrentView('scan'); // Auto-switch to scan view
    try {
      const response = await submitScan(request);
      if (response.success && response.result) {
        setScanResult(response.result);
      } else {
        setError(response.error || 'Unknown error occurred');
      }
    } catch (err: any) {
      setError(err.message || 'Failed to submit scan');
    } finally {
      setLoading(false);
    }
  };

  const handleRescan = () => {
    if (scanResult) {
      handleScanSubmit({ target: scanResult.target, target_type: scanResult.target_type as any });
    }
  };

  return (
    <DashboardLayout activeTab={currentView} onTabChange={setCurrentView as any}>
      {currentView === 'history' && <History />}
      {currentView === 'settings' && <Settings />}
      {currentView === 'scan' && (
        <div className="flex flex-col gap-xl animate-fade-in-up">
          <ScanForm onSubmit={handleScanSubmit} loading={loading} />
          
          {error && (
            <div className="bg-error-container border-l-4 border-error p-4 rounded shadow-sm mt-4">
              <h3 className="text-on-error-container font-title-lg flex items-center gap-2 mb-2">
                <span className="material-symbols-outlined">error</span>
                Scan Failed
              </h3>
              <p className="text-on-error-container font-body-md">{error}</p>
            </div>
          )}
          
          {scanResult && <ScanResult result={scanResult} onRescan={handleRescan} />}
        </div>
      )}
    </DashboardLayout>
  );
}

export default App;
