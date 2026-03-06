import { Suspense, lazy } from 'react';
import { BrowserRouter, Routes, Route } from 'react-router-dom';
import { Layout } from './components/Layout';
import { Home } from './pages/Home';

const HowItWorks = lazy(() => import('./pages/HowItWorks').then((module) => ({ default: module.HowItWorks })));
const Developers = lazy(() => import('./pages/Developers').then((module) => ({ default: module.Developers })));
const Dashboard = lazy(() => import('./pages/Dashboard').then((module) => ({ default: module.Dashboard })));
const Partners = lazy(() => import('./pages/Partners').then((module) => ({ default: module.Partners })));
const Pricing = lazy(() => import('./pages/Pricing').then((module) => ({ default: module.Pricing })));
const Proof = lazy(() => import('./pages/Proof').then((module) => ({ default: module.Proof })));
const Status = lazy(() => import('./pages/Status').then((module) => ({ default: module.Status })));
const RiskPolicy = lazy(() => import('./pages/RiskPolicy').then((module) => ({ default: module.RiskPolicy })));
const PrivateEthereumRpc = lazy(() =>
  import('./pages/PrivateEthereumRpc').then((module) => ({ default: module.PrivateEthereumRpc })),
);
const GaslessEthereumTransactions = lazy(() =>
  import('./pages/GaslessEthereumTransactions').then((module) => ({ default: module.GaslessEthereumTransactions })),
);
const MevProtection = lazy(() => import('./pages/MevProtection').then((module) => ({ default: module.MevProtection })));
const TermsOfService = lazy(() => import('./pages/TermsOfService').then((module) => ({ default: module.TermsOfService })));

function RouteFallback() {
  return (
    <div className="flex min-h-[40vh] items-center justify-center px-6">
      <div className="rounded-2xl border border-zinc-200 bg-white px-5 py-3 text-sm font-medium text-zinc-600 shadow-sm">
        Loading page...
      </div>
    </div>
  );
}

export default function App() {
  return (
    <BrowserRouter>
      <Suspense fallback={<RouteFallback />}>
        <Routes>
          <Route path="/" element={<Layout />}>
            <Route index element={<Home />} />
            <Route path="how-it-works" element={<HowItWorks />} />
            <Route path="developers" element={<Developers />} />
            <Route path="dashboard" element={<Dashboard />} />
            <Route path="partners" element={<Partners />} />
            <Route path="pricing" element={<Pricing />} />
            <Route path="proof" element={<Proof />} />
            <Route path="status" element={<Status />} />
            <Route path="risk-policy" element={<RiskPolicy />} />
            <Route path="private-ethereum-rpc" element={<PrivateEthereumRpc />} />
            <Route path="gasless-ethereum-transactions" element={<GaslessEthereumTransactions />} />
            <Route path="mev-protection" element={<MevProtection />} />
            <Route path="terms" element={<TermsOfService />} />
          </Route>
        </Routes>
      </Suspense>
    </BrowserRouter>
  );
}
