import { BrowserRouter, Routes, Route } from 'react-router-dom';
import { Layout } from './components/Layout';
import { Home } from './pages/Home';
import { HowItWorks } from './pages/HowItWorks';
import { Developers } from './pages/Developers';
import { Dashboard } from './pages/Dashboard';
import { Partners } from './pages/Partners';
import { Status } from './pages/Status';
import { RiskPolicy } from './pages/RiskPolicy';
import { PrivateEthereumRpc } from './pages/PrivateEthereumRpc';
import { GaslessEthereumTransactions } from './pages/GaslessEthereumTransactions';
import { MevProtection } from './pages/MevProtection';
import { TermsOfService } from './pages/TermsOfService';

export default function App() {
  return (
    <BrowserRouter>
      <Routes>
        <Route path="/" element={<Layout />}>
          <Route index element={<Home />} />
          <Route path="how-it-works" element={<HowItWorks />} />
          <Route path="developers" element={<Developers />} />
          <Route path="dashboard" element={<Dashboard />} />
          <Route path="partners" element={<Partners />} />
          <Route path="status" element={<Status />} />
          <Route path="risk-policy" element={<RiskPolicy />} />
          <Route path="private-ethereum-rpc" element={<PrivateEthereumRpc />} />
          <Route path="gasless-ethereum-transactions" element={<GaslessEthereumTransactions />} />
          <Route path="mev-protection" element={<MevProtection />} />
          <Route path="terms" element={<TermsOfService />} />
        </Route>
      </Routes>
    </BrowserRouter>
  );
}
