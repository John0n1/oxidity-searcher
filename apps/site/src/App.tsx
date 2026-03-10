import React, { useState, useEffect } from 'react';
import { BrowserRouter, Routes, Route, Link, useLocation } from 'react-router-dom';
import { motion, AnimatePresence } from 'motion/react';
import {
  ArrowRight,
  CheckCircle2,
  Chrome,
  Download,
  ExternalLink,
  Fingerprint,
  Globe,
  Network,
  Smartphone,
  Terminal,
  Shield,
  Lock,
  Fuel,
  Mail,
  HelpCircle,
  ChevronDown,
  ChevronUp
} from 'lucide-react';

const networks = [
  { name: 'Ethereum', icon: 'https://cryptologos.cc/logos/ethereum-eth-logo.svg?v=029' },
  { name: 'BNB Smart Chain', icon: 'https://cryptologos.cc/logos/bnb-bnb-logo.svg?v=029' },
  { name: 'Polygon', icon: 'https://cryptologos.cc/logos/polygon-matic-logo.svg?v=029' },
  { name: 'Base', icon: 'https://raw.githubusercontent.com/base-org/brand-kit/main/logo/symbol/Base_Symbol_Blue.svg' },
  { name: 'Avalanche', icon: 'https://cryptologos.cc/logos/avalanche-avax-logo.svg?v=029' },
  { name: 'Optimism', icon: 'https://cryptologos.cc/logos/optimism-ethereum-op-logo.svg?v=029' },
  { name: 'Arbitrum', icon: 'https://cryptologos.cc/logos/arbitrum-arb-logo.svg?v=029' },
  { name: 'Solana', icon: 'https://cryptologos.cc/logos/solana-sol-logo.svg?v=029' },
  { name: 'PulseChain', icon: 'https://cryptologos.cc/logos/pulsechain-pls-logo.png' },
  { name: 'Linea', icon: 'https://raw.githubusercontent.com/Consensys/linea-brand-kit/main/logo/logomark/linea-logomark-black.svg' },
  { name: 'Unichain', icon: 'https://cryptologos.cc/logos/uniswap-uni-logo.png' },
];

const CHROME_EXTENSION_URL = '/downloads/oxidity-wallet-extension.zip';
const ANDROID_APK_URL = `/downloads/oxidity-wallet-release.apk?v=${__OXIDITY_WALLET_VERSION__}`;
const WEB_WALLET_URL = 'https://wallet.oxidity.io';

const ChainIcon = ({ name, src }: { name: string; src?: string }) => {
  const [error, setError] = useState(false);
  
  if (!src || error) {
    return (
      <div className="w-5 h-5 rounded-full bg-[var(--color-oxidity-border)] flex items-center justify-center text-[10px] font-bold text-white shrink-0">
        {name.charAt(0)}
      </div>
    );
  }
  
  return (
    <img 
      src={src} 
      alt={name} 
      className="w-5 h-5 rounded-full shrink-0 bg-white object-contain p-[2px]" 
      onError={() => setError(true)} 
      referrerPolicy="no-referrer"
    />
  );
};

const AndroidLogo = ({ className }: { className?: string }) => (
  <svg viewBox="0 0 24 24" className={className} fill="currentColor">
    <path d="M17.523 15.3414c-.5511 0-.9993-.4486-.9993-.9997s.4483-.9993.9993-.9993c.5511 0 .9993.4482.9993.9993.0004.5511-.4482.9997-.9993.9997m-11.046 0c-.5511 0-.9993-.4486-.9993-.9997s.4482-.9993.9993-.9993c.5511 0 .9993.4482.9993.9993 0 .5511-.4482.9997-.9993.9997m11.4045-6.02l1.9973-3.4592a.416.416 0 00-.1521-.5676.416.416 0 00-.5676.1521l-2.022 3.503C15.5902 8.244 13.8533 7.851 12 7.851c-1.8533 0-3.5902.393-5.1371 1.0997L4.841 5.4477a.416.416 0 00-.5676-.1521.416.416 0 00-.1521.5676l1.9973 3.4592C2.6889 11.1867.3432 14.6589 0 18.761h24c-.3432-4.1021-2.6889-7.5743-6.1185-9.4396"/>
  </svg>
);

const OxidityLogo = ({ className }: { className?: string }) => (
  <svg viewBox="0 0 200 200" fill="none" xmlns="http://www.w3.org/2000/svg" className={className}>
    <circle cx="100" cy="100" r="75" stroke="currentColor" strokeWidth="20" />
    <path d="M88 25 L108 95 L98 95 L108 115 L98 115 L118 175" stroke="currentColor" strokeWidth="12" strokeLinejoin="miter" strokeLinecap="square" />
  </svg>
);

const ScrollToTop = () => {
  const { pathname } = useLocation();
  useEffect(() => {
    window.scrollTo(0, 0);
  }, [pathname]);
  return null;
};

const Layout = ({ children }: { children: React.ReactNode }) => {
  return (
    <div className="min-h-screen bg-[var(--color-oxidity-bg)] text-[var(--color-oxidity-text)] selection:bg-[var(--color-oxidity-accent)] selection:text-white font-sans overflow-x-hidden flex flex-col">
      {/* Navigation */}
      <nav className="fixed top-0 w-full z-50 glass-panel border-x-0 border-t-0 border-b-[var(--color-oxidity-border)]">
        <div className="max-w-7xl mx-auto px-6 h-16 flex items-center justify-between">
          <Link to="/" className="flex items-center gap-2">
            <div className="w-8 h-8 rounded-lg bg-[var(--color-oxidity-accent)] flex items-center justify-center">
              <OxidityLogo className="w-5 h-5 text-white" />
            </div>
            <span className="font-bold text-xl tracking-tight">Oxidity</span>
          </Link>
          <div className="hidden md:flex items-center gap-6 text-sm font-medium text-[var(--color-oxidity-muted)]">
            <Link to="/#advantage" className="hover:text-white transition-colors">Advantage</Link>
            <Link to="/#platforms" className="hover:text-white transition-colors">Platforms</Link>
            <Link to="/#networks" className="hover:text-white transition-colors">Networks</Link>
            <Link to="/support" className="hover:text-white transition-colors">Support</Link>
            <Link to="/#download" className="text-[var(--color-oxidity-accent)] hover:text-[var(--color-oxidity-accent-hover)] transition-colors">Download</Link>
          </div>
        </div>
      </nav>

      <main className="flex-grow pt-16">
        {children}
      </main>

      {/* Footer */}
      <footer className="py-12 px-6 border-t border-[var(--color-oxidity-border)] bg-[var(--color-oxidity-card)]/30">
        <div className="max-w-7xl mx-auto grid grid-cols-1 md:grid-cols-4 gap-8 mb-8">
          <div className="col-span-1 md:col-span-2">
            <Link to="/" className="flex items-center gap-2 mb-4">
              <OxidityLogo className="w-6 h-6 text-[var(--color-oxidity-accent)]" />
              <span className="font-bold tracking-tight text-lg">Oxidity</span>
            </Link>
            <p className="text-[var(--color-oxidity-muted)] text-sm max-w-sm">
              The ultimate private execution environment. Protect your trades from MEV, enjoy sponsored gas, and experience uncompromising security.
            </p>
          </div>
          <div>
            <h4 className="font-bold mb-4">Product</h4>
            <ul className="space-y-2 text-sm text-[var(--color-oxidity-muted)]">
              <li><Link to="/#download" className="hover:text-white transition-colors">Chrome Extension</Link></li>
              <li><Link to="/#download" className="hover:text-white transition-colors">Android APK</Link></li>
              <li><Link to="/#download" className="hover:text-white transition-colors">Web Wallet</Link></li>
            </ul>
          </div>
          <div>
            <h4 className="font-bold mb-4">Legal & Support</h4>
            <ul className="space-y-2 text-sm text-[var(--color-oxidity-muted)]">
              <li><Link to="/support" className="hover:text-white transition-colors">Support & FAQ</Link></li>
              <li><Link to="/privacy" className="hover:text-white transition-colors">Privacy Policy</Link></li>
              <li><Link to="/terms" className="hover:text-white transition-colors">Terms of Service</Link></li>
              <li><a href="mailto:support@oxidity.io" className="hover:text-white transition-colors">support@oxidity.io</a></li>
            </ul>
          </div>
        </div>
        <div className="max-w-7xl mx-auto pt-8 border-t border-[var(--color-oxidity-border)] flex flex-col md:flex-row items-center justify-between gap-4 text-sm text-[var(--color-oxidity-muted)]">
          <div>&copy; {new Date().getFullYear()} Oxidity Wallet. All rights reserved.</div>
        </div>
      </footer>
    </div>
  );
};

const Home = () => {
  const { hash } = useLocation();

  useEffect(() => {
    if (hash) {
      const element = document.getElementById(hash.replace('#', ''));
      if (element) {
        element.scrollIntoView({ behavior: 'smooth' });
      }
    }
  }, [hash]);

  return (
    <>
      {/* Hero Section */}
      <section className="pt-24 pb-20 px-6 relative">
        {/* Background glow */}
        <div className="absolute top-1/2 left-1/2 -translate-x-1/2 -translate-y-1/2 w-[600px] h-[600px] bg-[var(--color-oxidity-accent)]/15 rounded-full blur-[120px] pointer-events-none" />
        
        <div className="max-w-4xl mx-auto text-center relative z-10">
          <motion.div
            initial={{ opacity: 0, y: 20 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ duration: 0.5 }}
            className="inline-flex items-center gap-2 px-3 py-1 rounded-full border border-[var(--color-oxidity-border)] bg-[var(--color-oxidity-card)] text-xs font-mono text-[var(--color-oxidity-muted)] mb-8"
          >
            <Shield className="w-3 h-3 text-[var(--color-oxidity-accent)]" />
            <span>Private Execution Wallet</span>
          </motion.div>
          
          <motion.h1
            initial={{ opacity: 0, y: 20 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ duration: 0.5, delay: 0.1 }}
            className="text-5xl md:text-7xl font-bold tracking-tighter mb-6 text-gradient"
          >
            Trade securely. <br className="hidden md:block" />Execute privately.
          </motion.h1>
          
          <motion.p
            initial={{ opacity: 0, y: 20 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ duration: 0.5, delay: 0.2 }}
            className="text-lg md:text-xl text-[var(--color-oxidity-muted)] mb-12 max-w-3xl mx-auto leading-relaxed"
          >
            Oxidity is the ultimate execution environment. Protect your trades from MEV, enjoy sponsored gas, and experience uncompromising security across Chrome, Android, and the Web.
          </motion.p>
          
          <motion.div
            id="download"
            initial={{ opacity: 0, y: 20 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ duration: 0.5, delay: 0.3 }}
            className="flex flex-col sm:flex-row items-center justify-center gap-4"
          >
            <a
              href={CHROME_EXTENSION_URL}
              className="w-full sm:w-auto flex items-center justify-center gap-2 px-6 py-3 rounded-lg bg-[var(--color-oxidity-accent)] text-white font-medium hover:bg-[var(--color-oxidity-accent-hover)] transition-colors shadow-[0_0_20px_rgba(41,98,255,0.3)]"
            >
              <Chrome className="w-5 h-5" />
              <span>Download Chrome Build</span>
            </a>
            <a
              href={ANDROID_APK_URL}
              className="w-full sm:w-auto flex items-center justify-center gap-2 px-6 py-3 rounded-lg bg-[var(--color-oxidity-card)] border border-[var(--color-oxidity-border)] text-white hover:bg-[var(--color-oxidity-border)] transition-colors"
            >
              <AndroidLogo className="w-5 h-5" />
              <span>Download Android APK</span>
            </a>
            <a
              href={WEB_WALLET_URL}
              target="_blank"
              rel="noreferrer"
              className="w-full sm:w-auto flex items-center justify-center gap-2 px-6 py-3 rounded-lg bg-transparent text-[var(--color-oxidity-muted)] hover:text-white transition-colors"
            >
              <span>Open Web Wallet</span>
              <ArrowRight className="w-4 h-4" />
            </a>
          </motion.div>
        </div>
      </section>

      {/* The Execution Advantage */}
      <section id="advantage" className="py-24 px-6 border-y border-[var(--color-oxidity-border)] bg-[var(--color-oxidity-card)]/30 relative overflow-hidden">
        <div className="absolute top-0 right-0 w-[500px] h-[500px] bg-[var(--color-oxidity-accent)]/5 rounded-full blur-[100px] pointer-events-none" />
        <div className="max-w-7xl mx-auto relative z-10">
          <div className="text-center mb-16">
            <h2 className="text-3xl md:text-4xl font-bold tracking-tight mb-4">The Execution Advantage</h2>
            <p className="text-[var(--color-oxidity-muted)] max-w-2xl mx-auto">
              Oxidity isn't just another wallet. It's a secure execution environment engineered to protect your assets and optimize your trades.
            </p>
          </div>

          <div className="grid grid-cols-1 md:grid-cols-3 gap-8">
            {/* Private Execution */}
            <div className="glass-panel p-8 rounded-2xl hover:border-[var(--color-oxidity-accent)]/50 transition-colors group">
              <div className="w-12 h-12 rounded-xl bg-[var(--color-oxidity-accent)]/10 border border-[var(--color-oxidity-accent)]/20 flex items-center justify-center mb-6 group-hover:scale-110 transition-transform">
                <Shield className="w-6 h-6 text-[var(--color-oxidity-accent)]" />
              </div>
              <h3 className="text-xl font-bold mb-3">Private Execution</h3>
              <p className="text-[var(--color-oxidity-muted)] leading-relaxed">
                Your trades are yours. Oxidity routes transactions through private mempools (like Flashbots and MEV-Share), shielding you from front-running, sandwich attacks, and predatory MEV bots.
              </p>
            </div>

            {/* Gas Sponsorship */}
            <div className="glass-panel p-8 rounded-2xl hover:border-[var(--color-oxidity-accent)]/50 transition-colors group">
              <div className="w-12 h-12 rounded-xl bg-[var(--color-oxidity-accent)]/10 border border-[var(--color-oxidity-accent)]/20 flex items-center justify-center mb-6 group-hover:scale-110 transition-transform">
                <Fuel className="w-6 h-6 text-[var(--color-oxidity-accent)]" />
              </div>
              <h3 className="text-xl font-bold mb-3">Gas Sponsorship</h3>
              <p className="text-[var(--color-oxidity-muted)] leading-relaxed">
                Out of native tokens? No problem. Native Account Abstraction (ERC-4337) and Paymaster integration let you pay gas in stablecoins, or enjoy fully sponsored transactions from supported dApps.
              </p>
            </div>

            {/* Hardware Security */}
            <div className="glass-panel p-8 rounded-2xl hover:border-[var(--color-oxidity-accent)]/50 transition-colors group">
              <div className="w-12 h-12 rounded-xl bg-[var(--color-oxidity-accent)]/10 border border-[var(--color-oxidity-accent)]/20 flex items-center justify-center mb-6 group-hover:scale-110 transition-transform">
                <Lock className="w-6 h-6 text-[var(--color-oxidity-accent)]" />
              </div>
              <h3 className="text-xl font-bold mb-3">Hardware-Grade Security</h3>
              <p className="text-[var(--color-oxidity-muted)] leading-relaxed">
                Keys never leave your device. Secured by Android's hardware-backed Keystore, biometric enclaves, and AES-256 encrypted local storage on Chrome.
              </p>
            </div>
          </div>
        </div>
      </section>

      {/* Stats Section */}
      <section className="py-12 px-6 border-b border-[var(--color-oxidity-border)] bg-[var(--color-oxidity-bg)]">
        <div className="max-w-7xl mx-auto grid grid-cols-1 md:grid-cols-3 gap-8 divide-y md:divide-y-0 md:divide-x divide-[var(--color-oxidity-border)]">
          <div className="flex flex-col items-center text-center md:px-8 pt-8 md:pt-0 first:pt-0">
            <div className="w-12 h-12 rounded-full bg-[var(--color-oxidity-card)] border border-[var(--color-oxidity-border)] flex items-center justify-center mb-4">
              <Network className="w-6 h-6 text-[var(--color-oxidity-accent)]" />
            </div>
            <div className="text-4xl font-bold font-mono mb-2">11</div>
            <p className="text-sm text-[var(--color-oxidity-muted)]">supported wallet networks across EVM and Solana</p>
          </div>
          
          <div className="flex flex-col items-center text-center md:px-8 pt-8 md:pt-0">
            <div className="w-12 h-12 rounded-full bg-[var(--color-oxidity-card)] border border-[var(--color-oxidity-border)] flex items-center justify-center mb-4">
              <Terminal className="w-6 h-6 text-[var(--color-oxidity-accent)]" />
            </div>
            <div className="text-xl font-bold mb-2">Rust</div>
            <p className="text-sm text-[var(--color-oxidity-muted)] font-mono bg-[var(--color-oxidity-card)] px-2 py-1 rounded border border-[var(--color-oxidity-border)] mb-2">axum + alloy</p>
            <p className="text-sm text-[var(--color-oxidity-muted)]">backend for EVM wallet operations</p>
          </div>
          
          <div className="flex flex-col items-center text-center md:px-8 pt-8 md:pt-0">
            <div className="w-12 h-12 rounded-full bg-[var(--color-oxidity-card)] border border-[var(--color-oxidity-border)] flex items-center justify-center mb-4">
              <Fingerprint className="w-6 h-6 text-[var(--color-oxidity-accent)]" />
            </div>
            <div className="text-xl font-bold mb-2">Biometric</div>
            <p className="text-sm text-[var(--color-oxidity-muted)]">fingerprint/device credential unlock on Android</p>
          </div>
        </div>
      </section>

      {/* Platforms Section */}
      <section id="platforms" className="py-24 px-6">
        <div className="max-w-7xl mx-auto">
          <div className="text-center mb-16">
            <h2 className="text-3xl md:text-4xl font-bold tracking-tight mb-4">Three Surfaces. One Wallet.</h2>
            <p className="text-[var(--color-oxidity-muted)] max-w-2xl mx-auto">Access your portfolio and execute trades seamlessly across your browser, mobile device, and the web.</p>
          </div>

          <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
            {/* Chrome Extension */}
            <div className="glass-panel rounded-2xl p-8 flex flex-col relative overflow-hidden group">
              <div className="absolute top-0 right-0 p-8 opacity-5 group-hover:opacity-10 transition-opacity">
                <Chrome className="w-32 h-32" />
              </div>
              
              <div className="w-12 h-12 rounded-xl bg-[var(--color-oxidity-card)] border border-[var(--color-oxidity-border)] flex items-center justify-center mb-6 relative z-10">
                <Chrome className="w-6 h-6 text-white" />
              </div>
              
              <h3 className="text-2xl font-bold mb-2 relative z-10">Chrome Extension</h3>
              <p className="text-[var(--color-oxidity-muted)] mb-8 flex-grow relative z-10">
                Installs the current extension build for Chromium-based browsers. The internal runtime opens as a <code className="text-xs font-mono bg-[var(--color-oxidity-bg)] px-1 py-0.5 rounded border border-[var(--color-oxidity-border)]">chrome-extension://.../home.html</code> page after install.
              </p>
              
              <div className="space-y-3 mb-8 relative z-10">
                <div className="flex items-center gap-3 text-sm">
                  <CheckCircle2 className="w-4 h-4 text-[var(--color-oxidity-accent)]" />
                  <span>Popup entry: <code className="font-mono text-xs text-[var(--color-oxidity-muted)]">home.html</code></span>
                </div>
                <div className="flex items-center gap-3 text-sm">
                  <CheckCircle2 className="w-4 h-4 text-[var(--color-oxidity-accent)]" />
                  <span>Storage enabled</span>
                </div>
                <div className="flex items-center gap-3 text-sm">
                  <CheckCircle2 className="w-4 h-4 text-[var(--color-oxidity-accent)]" />
                  <span>Wallet API ready</span>
                </div>
              </div>
              
              <a
                href={CHROME_EXTENSION_URL}
                className="w-full flex items-center justify-center gap-2 py-3 rounded-lg bg-[var(--color-oxidity-card)] border border-[var(--color-oxidity-border)] hover:bg-[var(--color-oxidity-border)] transition-colors relative z-10"
              >
                <Download className="w-4 h-4" />
                <span className="font-mono text-xs">Get oxidity-wallet-extension.zip</span>
              </a>
            </div>

            {/* Android APK */}
            <div className="glass-panel rounded-2xl p-8 flex flex-col relative overflow-hidden group">
              <div className="absolute top-0 right-0 p-8 opacity-5 group-hover:opacity-10 transition-opacity">
                <AndroidLogo className="w-32 h-32" />
              </div>
              
              <div className="w-12 h-12 rounded-xl bg-[var(--color-oxidity-card)] border border-[var(--color-oxidity-border)] flex items-center justify-center mb-6 relative z-10">
                <AndroidLogo className="w-6 h-6 text-white" />
              </div>
              
              <h3 className="text-2xl font-bold mb-2 relative z-10">Android APK</h3>
              <p className="text-[var(--color-oxidity-muted)] mb-8 flex-grow relative z-10">
                Native Capacitor Android build with secure storage, biometric authentication, and the same Oxidity wallet frontend packaged inside the app shell.
              </p>
              
              <div className="space-y-3 mb-8 relative z-10">
                <div className="flex items-center gap-3 text-sm">
                  <CheckCircle2 className="w-4 h-4 text-[var(--color-oxidity-accent)]" />
                  <span>Fingerprint unlock</span>
                </div>
                <div className="flex items-center gap-3 text-sm">
                  <CheckCircle2 className="w-4 h-4 text-[var(--color-oxidity-accent)]" />
                  <span>Secure storage</span>
                </div>
                <div className="flex items-center gap-3 text-sm">
                  <CheckCircle2 className="w-4 h-4 text-[var(--color-oxidity-accent)]" />
                  <span>Release build ready</span>
                </div>
              </div>
              
              <a
                href={ANDROID_APK_URL}
                className="w-full flex items-center justify-center gap-2 py-3 rounded-lg bg-[var(--color-oxidity-card)] border border-[var(--color-oxidity-border)] hover:bg-[var(--color-oxidity-border)] transition-colors relative z-10"
              >
                <Download className="w-4 h-4" />
                <span className="font-mono text-xs">Get oxidity-wallet-release.apk</span>
              </a>
            </div>

            {/* Hosted Wallet */}
            <div className="glass-panel rounded-2xl p-8 flex flex-col relative overflow-hidden group">
              <div className="absolute top-0 right-0 p-8 opacity-5 group-hover:opacity-10 transition-opacity">
                <Globe className="w-32 h-32" />
              </div>
              
              <div className="w-12 h-12 rounded-xl bg-[var(--color-oxidity-card)] border border-[var(--color-oxidity-border)] flex items-center justify-center mb-6 relative z-10">
                <Globe className="w-6 h-6 text-white" />
              </div>
              
              <h3 className="text-2xl font-bold mb-2 relative z-10">Hosted Wallet</h3>
              <p className="text-[var(--color-oxidity-muted)] mb-8 flex-grow relative z-10">
                Opens the same wallet frontend on <code className="text-xs font-mono bg-[var(--color-oxidity-bg)] px-1 py-0.5 rounded border border-[var(--color-oxidity-border)]">wallet.oxidity.io</code>, backed by the Oxidity wallet API and the configured public RPC infrastructure.
              </p>
              
              <div className="space-y-3 mb-8 relative z-10">
                <div className="flex items-center gap-3 text-sm">
                  <CheckCircle2 className="w-4 h-4 text-[var(--color-oxidity-accent)]" />
                  <span>Portfolio reads</span>
                </div>
                <div className="flex items-center gap-3 text-sm">
                  <CheckCircle2 className="w-4 h-4 text-[var(--color-oxidity-accent)]" />
                  <span>Send flow</span>
                </div>
                <div className="flex items-center gap-3 text-sm">
                  <CheckCircle2 className="w-4 h-4 text-[var(--color-oxidity-accent)]" />
                  <span>AI market assistant</span>
                </div>
              </div>
              
              <a
                href={WEB_WALLET_URL}
                target="_blank"
                rel="noreferrer"
                className="w-full flex items-center justify-center gap-2 py-3 rounded-lg bg-[var(--color-oxidity-card)] border border-[var(--color-oxidity-border)] hover:bg-[var(--color-oxidity-border)] transition-colors relative z-10"
              >
                <ExternalLink className="w-4 h-4" />
                <span className="font-mono text-xs">Launch wallet.oxidity.io</span>
              </a>
            </div>
          </div>
        </div>
      </section>

      {/* Networks Section */}
      <section id="networks" className="py-24 px-6 border-t border-[var(--color-oxidity-border)] bg-[var(--color-oxidity-card)]/30 overflow-hidden">
        <div className="max-w-7xl mx-auto">
          <div className="text-center mb-12">
            <h2 className="text-3xl font-bold tracking-tight mb-4">Supported Networks</h2>
            <p className="text-[var(--color-oxidity-muted)]">Oxidity Wallet currently supports EVM networks plus Solana.</p>
          </div>
          
          <div className="marquee-container py-8">
            <div className="marquee-content">
              {networks.map((network, i) => (
                <div 
                  key={`a-${i}`}
                  className="flex items-center gap-2 flex-shrink-0 px-6 py-3 rounded-full border border-[var(--color-oxidity-border)] bg-[var(--color-oxidity-bg)] text-sm font-medium whitespace-nowrap"
                >
                  <ChainIcon name={network.name} src={network.icon} />
                  <span>{network.name}</span>
                </div>
              ))}
            </div>
            <div className="marquee-content" aria-hidden="true">
              {networks.map((network, i) => (
                <div 
                  key={`b-${i}`}
                  className="flex items-center gap-2 flex-shrink-0 px-6 py-3 rounded-full border border-[var(--color-oxidity-border)] bg-[var(--color-oxidity-bg)] text-sm font-medium whitespace-nowrap"
                >
                  <ChainIcon name={network.name} src={network.icon} />
                  <span>{network.name}</span>
                </div>
              ))}
            </div>
          </div>
        </div>
      </section>

      {/* Final CTA */}
      <section className="py-24 px-6 relative overflow-hidden border-t border-[var(--color-oxidity-border)]">
        <div className="absolute inset-0 bg-[var(--color-oxidity-accent)]/5" />
        <div className="absolute top-1/2 left-1/2 -translate-x-1/2 -translate-y-1/2 w-[800px] h-[400px] bg-[var(--color-oxidity-accent)]/10 rounded-full blur-[100px] pointer-events-none" />
        
        <div className="max-w-4xl mx-auto text-center relative z-10">
          <h2 className="text-4xl md:text-5xl font-bold tracking-tight mb-6">Ready to upgrade your execution?</h2>
          <p className="text-xl text-[var(--color-oxidity-muted)] mb-10 max-w-2xl mx-auto">
            Stop leaking value to MEV bots. Join the next generation of traders protecting their alpha with Oxidity.
          </p>
          <div className="flex flex-col sm:flex-row items-center justify-center gap-4">
            <a
              href={CHROME_EXTENSION_URL}
              className="px-8 py-4 rounded-xl bg-[var(--color-oxidity-accent)] text-white font-bold hover:bg-[var(--color-oxidity-accent-hover)] transition-all hover:scale-105 shadow-[0_0_30px_rgba(41,98,255,0.4)] flex items-center gap-2"
            >
              <Download className="w-5 h-5" />
              <span>Install Oxidity Free</span>
            </a>
          </div>
        </div>
      </section>
    </>
  );
};

const Privacy = () => (
  <div className="max-w-3xl mx-auto px-6 py-20">
    <h1 className="text-4xl font-bold mb-8">Privacy Policy</h1>
    <div className="space-y-6 text-[var(--color-oxidity-muted)] leading-relaxed">
      <p>Last updated: {new Date().toLocaleDateString()}</p>
      
      <h2 className="text-2xl font-bold text-white mt-12 mb-4">1. Introduction</h2>
      <p>Oxidity ("we", "our", or "us") is committed to protecting your privacy. This Privacy Policy explains how your information is collected, used, and disclosed by Oxidity when you use our Chrome Extension, Android APK, or Web Wallet (collectively, the "Services").</p>
      
      <h2 className="text-2xl font-bold text-white mt-12 mb-4">2. Information We Do Not Collect</h2>
      <p>As a non-custodial, private execution wallet, we prioritize your privacy by design:</p>
      <ul className="list-disc pl-6 space-y-2">
        <li>We do not collect, store, or have access to your private keys or seed phrases.</li>
        <li>We do not track your IP address or associate it with your wallet addresses.</li>
        <li>We do not collect personal identification information (KYC) to use the core wallet features.</li>
      </ul>

      <h2 className="text-2xl font-bold text-white mt-12 mb-4">3. Information We Collect</h2>
      <p>We only collect information necessary to provide and improve our Services:</p>
      <ul className="list-disc pl-6 space-y-2">
        <li><strong>Public Blockchain Data:</strong> We read public blockchain data (balances, transaction history) to display your portfolio.</li>
        <li><strong>Anonymous Usage Data:</strong> We may collect aggregated, non-identifiable telemetry data to improve app performance and identify bugs.</li>
      </ul>

      <h2 className="text-2xl font-bold text-white mt-12 mb-4">4. Third-Party Services</h2>
      <p>Our Services interact with third-party RPC providers and private mempools (e.g., Flashbots) to execute transactions. Your interactions with these services are governed by their respective privacy policies.</p>

      <h2 className="text-2xl font-bold text-white mt-12 mb-4">5. Contact Us</h2>
      <p>If you have any questions about this Privacy Policy, please contact us at <a href="mailto:support@oxidity.io" className="text-[var(--color-oxidity-accent)] hover:underline">support@oxidity.io</a>.</p>
    </div>
  </div>
);

const Terms = () => (
  <div className="max-w-3xl mx-auto px-6 py-20">
    <h1 className="text-4xl font-bold mb-8">Terms of Service</h1>
    <div className="space-y-6 text-[var(--color-oxidity-muted)] leading-relaxed">
      <p>Last updated: {new Date().toLocaleDateString()}</p>
      
      <h2 className="text-2xl font-bold text-white mt-12 mb-4">1. Acceptance of Terms</h2>
      <p>By downloading, accessing, or using the Oxidity Wallet, you agree to be bound by these Terms of Service. If you do not agree to these terms, do not use our Services.</p>
      
      <h2 className="text-2xl font-bold text-white mt-12 mb-4">2. Non-Custodial Nature</h2>
      <p>Oxidity is a non-custodial wallet software. You are solely responsible for the custody of your cryptographic private keys and seed phrases. We cannot recover your funds if you lose your keys.</p>

      <h2 className="text-2xl font-bold text-white mt-12 mb-4">3. Assumption of Risk</h2>
      <p>You acknowledge that using blockchain technology involves inherent risks, including but not limited to smart contract vulnerabilities, regulatory changes, and market volatility. You agree that Oxidity is not responsible for any losses incurred.</p>

      <h2 className="text-2xl font-bold text-white mt-12 mb-4">4. Acceptable Use</h2>
      <p>You agree not to use the Services for any illegal activities, including but not limited to money laundering, terrorist financing, or interacting with sanctioned entities.</p>

      <h2 className="text-2xl font-bold text-white mt-12 mb-4">5. Disclaimer of Warranties</h2>
      <p>The Services are provided "AS IS" and "AS AVAILABLE" without any warranties of any kind, either express or implied, including but not limited to implied warranties of merchantability or fitness for a particular purpose.</p>
    </div>
  </div>
);

const FaqItem = ({ question, answer }: { question: string, answer: string }) => {
  const [isOpen, setIsOpen] = useState(false);
  return (
    <div className="border border-[var(--color-oxidity-border)] rounded-xl bg-[var(--color-oxidity-card)] overflow-hidden">
      <button 
        onClick={() => setIsOpen(!isOpen)}
        className="w-full px-6 py-4 flex items-center justify-between text-left hover:bg-[var(--color-oxidity-border)]/50 transition-colors"
      >
        <span className="font-medium text-white">{question}</span>
        {isOpen ? <ChevronUp className="w-5 h-5 text-[var(--color-oxidity-muted)]" /> : <ChevronDown className="w-5 h-5 text-[var(--color-oxidity-muted)]" />}
      </button>
      <AnimatePresence>
        {isOpen && (
          <motion.div
            initial={{ height: 0, opacity: 0 }}
            animate={{ height: 'auto', opacity: 1 }}
            exit={{ height: 0, opacity: 0 }}
            className="px-6 pb-4 text-[var(--color-oxidity-muted)] leading-relaxed"
          >
            {answer}
          </motion.div>
        )}
      </AnimatePresence>
    </div>
  );
};

const Support = () => (
  <div className="max-w-4xl mx-auto px-6 py-20">
    <div className="text-center mb-16">
      <div className="w-16 h-16 rounded-2xl bg-[var(--color-oxidity-accent)]/10 border border-[var(--color-oxidity-accent)]/20 flex items-center justify-center mx-auto mb-6">
        <HelpCircle className="w-8 h-8 text-[var(--color-oxidity-accent)]" />
      </div>
      <h1 className="text-4xl md:text-5xl font-bold mb-4">How can we help?</h1>
      <p className="text-xl text-[var(--color-oxidity-muted)]">Find answers to common questions or reach out to our team.</p>
    </div>

    <div className="grid grid-cols-1 md:grid-cols-2 gap-12 mb-20">
      <div>
        <h2 className="text-2xl font-bold mb-6 flex items-center gap-2">
          <Mail className="w-6 h-6 text-[var(--color-oxidity-accent)]" />
          Contact Us
        </h2>
        <div className="glass-panel p-8 rounded-2xl">
          <p className="text-[var(--color-oxidity-muted)] mb-6">
            Our support team is available 24/7 to help you with any issues related to the Oxidity Wallet.
          </p>
          <a 
            href="mailto:support@oxidity.io" 
            className="inline-flex items-center gap-2 px-6 py-3 rounded-lg bg-[var(--color-oxidity-accent)] text-white font-medium hover:bg-[var(--color-oxidity-accent-hover)] transition-colors"
          >
            <Mail className="w-5 h-5" />
            Email support@oxidity.io
          </a>
          <p className="text-xs text-[var(--color-oxidity-muted)] mt-4">
            Typical response time: Under 2 hours.
          </p>
        </div>
      </div>

      <div>
        <h2 className="text-2xl font-bold mb-6">Frequently Asked Questions</h2>
        <div className="space-y-4">
          <FaqItem 
            question="Is Oxidity non-custodial?" 
            answer="Yes. Oxidity is fully non-custodial. Your private keys are encrypted and stored locally on your device. We never have access to your funds or your keys." 
          />
          <FaqItem 
            question="How does Private Execution work?" 
            answer="Instead of broadcasting your transactions to the public mempool where MEV bots can front-run or sandwich your trades, Oxidity routes them through private RPC endpoints (like Flashbots Protect). This ensures your trades are executed securely." 
          />
          <FaqItem 
            question="How do I get sponsored gas?" 
            answer="Oxidity supports ERC-4337 Account Abstraction. If you are interacting with a dApp that has a Paymaster configured, your gas fees will be automatically sponsored. Alternatively, you can choose to pay gas using stablecoins like USDC." 
          />
          <FaqItem 
            question="Can I import my existing wallet?" 
            answer="Yes. You can import any existing EVM wallet or a Solana wallet derived from your seed phrase, and you can also import an EVM private key directly." 
          />
        </div>
      </div>
    </div>
  </div>
);

export default function App() {
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    const timer = setTimeout(() => {
      setLoading(false);
    }, 500);
    return () => clearTimeout(timer);
  }, []);

  return (
    <BrowserRouter>
      <ScrollToTop />
      <AnimatePresence>
        {loading && (
          <motion.div
            initial={{ opacity: 1 }}
            exit={{ opacity: 0 }}
            transition={{ duration: 0.5, ease: "easeInOut" }}
            className="fixed inset-0 z-[100] bg-[var(--color-oxidity-bg)] flex flex-col items-center justify-center"
          >
            <motion.div
              initial={{ scale: 0.8, opacity: 0 }}
              animate={{ scale: 1, opacity: 1 }}
              transition={{ duration: 0.5 }}
              className="relative"
            >
              <motion.div
                animate={{ rotate: 360 }}
                transition={{ duration: 8, repeat: Infinity, ease: "linear" }}
                className="absolute inset-0 rounded-full border-t-2 border-[var(--color-oxidity-accent)] opacity-50 blur-sm"
              />
              <OxidityLogo className="w-24 h-24 text-[var(--color-oxidity-accent)] drop-shadow-[0_0_15px_rgba(41,98,255,0.5)]" />
            </motion.div>
            <motion.div
              initial={{ opacity: 0, y: 10 }}
              animate={{ opacity: 1, y: 0 }}
              transition={{ delay: 0.5 }}
              className="mt-6 font-mono text-sm text-[var(--color-oxidity-muted)] tracking-widest uppercase"
            >
              Initializing Secure Enclave...
            </motion.div>
          </motion.div>
        )}
      </AnimatePresence>

      <Layout>
        <Routes>
          <Route path="/" element={<Home />} />
          <Route path="/privacy" element={<Privacy />} />
          <Route path="/terms" element={<Terms />} />
          <Route path="/support" element={<Support />} />
        </Routes>
      </Layout>
    </BrowserRouter>
  );
}
