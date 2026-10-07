import { useState } from 'react';
import { MotionConfig } from 'framer-motion';
import { TopBar, type View } from './components/TopBar';
import { ScanView } from './components/ScanView';
import { History } from './components/History';
import { Settings } from './components/Settings';
import { NetworkSection } from './components/NetworkSection';
import { useScan } from './hooks/useScan';

function App() {
  const [view, setView] = useState<View>('scan');
  const scan = useScan();

  return (
    <MotionConfig reducedMotion="user">
      <TopBar view={view} onChange={setView} />
      <main className="mx-auto w-full max-w-6xl px-6 py-6">
        {view === 'scan' && <ScanView scan={scan} />}
        {view === 'network' && <NetworkSection />}
        {view === 'history' && <History />}
        {view === 'settings' && <Settings />}
      </main>
    </MotionConfig>
  );
}

export default App;
