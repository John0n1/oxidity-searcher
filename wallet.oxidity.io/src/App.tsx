import { BrowserRouter, Navigate, Route, Routes } from 'react-router-dom';
import { WalletShell } from '@/wallet/WalletShell';
import { LandingPage } from '@/views/LandingPage';
import { getRuntimeTarget } from '@/lib/platform';

export default function App() {
  if (getRuntimeTarget() !== 'web') {
    return <WalletShell embedded />;
  }

  return (
    <BrowserRouter>
      <Routes>
        <Route path="/" element={<LandingPage />} />
        <Route path="/app" element={<WalletShell />} />
        <Route path="*" element={<Navigate to="/" replace />} />
      </Routes>
    </BrowserRouter>
  );
}
