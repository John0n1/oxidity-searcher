import { Outlet, Link, useLocation } from 'react-router-dom';
import { Activity, Code, DollarSign, LayoutDashboard, Menu, Shield, Users, X } from 'lucide-react';
import { useEffect, useState } from 'react';
import { clsx, type ClassValue } from 'clsx';
import { twMerge } from 'tailwind-merge';
import { applySeo } from '../lib/seo';

export function cn(...inputs: ClassValue[]) {
  return twMerge(clsx(inputs));
}

export function Layout() {
  const [isMobileMenuOpen, setIsMobileMenuOpen] = useState(false);
  const location = useLocation();

  useEffect(() => {
    applySeo(location.pathname);
  }, [location.pathname]);

  useEffect(() => {
    const root = document.documentElement;
    root.classList.remove('theme-dark');
    root.style.colorScheme = 'light';
    window.localStorage.removeItem('mitander.theme');
  }, []);

  const navigation = [
    { name: 'Proof', href: '/proof', icon: Shield },
    { name: 'Private RPC', href: '/private-ethereum-rpc', icon: Code },
    { name: 'Developers', href: '/developers', icon: Code },
    { name: 'Pricing', href: '/pricing', icon: DollarSign },
    { name: 'Teams', href: '/partners', icon: Users },
    { name: 'Status', href: '/status', icon: Activity, liveIndicator: true },
  ];
  const isActive = (path: string) => location.pathname === path;

  return (
    <div className="relative min-h-screen bg-page text-zinc-900 font-sans flex flex-col overflow-x-hidden">
      <div className="starscape" aria-hidden="true">
        <div className="bg-mesh" />
        <div className="bg-aura" />
        <div className="bg-ribbon" />
        <div className="bg-wave" />
        <div className="bg-wave bg-wave-2" />
        <div className="bg-orb bg-orb-a" />
        <div className="bg-orb bg-orb-b" />
        <div className="day-sparkles day-sparkles-a" />
        <div className="day-sparkles day-sparkles-b" />
        <div className="sky-drift" />
        <div className="sky-falloff" />
        <div className="stars stars-far" />
        <div className="stars stars-mid" />
        <div className="stars stars-near" />
        <div className="stars-glow" />
        <div className="plane-trace plane-trace-a" />
        <div className="plane-trace plane-trace-b" />
      </div>
      <header className="relative sticky top-0 z-50 bg-shell backdrop-blur-md border-b border-zinc-200">
        <nav className="mx-auto max-w-7xl px-4 sm:px-6 lg:px-8" aria-label="Top">
          <div className="flex h-16 items-center justify-between">
            <div className="flex items-center">
              <Link to="/" className="flex items-center gap-2.5">
                <img src="/brand-mark.svg" alt="Oxidity logo" className="h-8 w-8 rounded-lg" />
                <div className="leading-none">
                  <span className="block text-xl font-semibold tracking-tight">Oxidity</span>
                  <span className="block text-[11px] font-medium uppercase tracking-[0.16em] text-zinc-500">Execution Infrastructure</span>
                </div>
              </Link>
              <div className="hidden ml-10 space-x-8 lg:block">
                {navigation.map((link) => (
                  <Link
                    key={link.name}
                    to={link.href}
                    className={cn(
                      "inline-flex items-center gap-2 text-sm font-medium transition-colors hover:text-zinc-900",
                      isActive(link.href) ? "text-zinc-900" : "text-zinc-500"
                    )}
                  >
                    {link.name}
                    {link.liveIndicator ? (
                      <span
                        className="inline-flex items-center rounded-full border border-emerald-200 bg-emerald-50 px-1.5 py-0.5 text-[10px] font-semibold uppercase tracking-[0.12em] text-emerald-700"
                        aria-label="Mainnet operational"
                        title="Mainnet operational"
                      >
                        <span className="mr-1 inline-block h-1.5 w-1.5 rounded-full bg-emerald-500" />
                        Live
                      </span>
                    ) : null}
                  </Link>
                ))}
              </div>
            </div>
            <div className="hidden lg:flex items-center gap-4">
              <Link
                to="/dashboard"
                className="text-sm font-medium text-zinc-500 transition-colors hover:text-zinc-900"
              >
                Dashboard
              </Link>
              <Link
                to="/pricing"
                className="rounded-lg border border-zinc-300 bg-white px-4 py-2 text-sm font-medium text-zinc-900 transition-colors hover:bg-zinc-50"
              >
                Pricing
              </Link>
              <Link
                to="/partners?requested=production"
                className="flex items-center gap-2 rounded-lg bg-zinc-900 px-4 py-2 text-sm font-medium text-white transition-colors hover:bg-zinc-800"
              >
                <Users className="w-4 h-4" />
                Talk to Us
              </Link>
            </div>
            <div className="flex lg:hidden">
              <button
                type="button"
                className="-m-2.5 inline-flex items-center justify-center rounded-md p-2.5 text-zinc-700"
                onClick={() => setIsMobileMenuOpen(!isMobileMenuOpen)}
              >
                <span className="sr-only">Open main menu</span>
                {isMobileMenuOpen ? (
                  <X className="h-6 w-6" aria-hidden="true" />
                ) : (
                  <Menu className="h-6 w-6" aria-hidden="true" />
                )}
              </button>
            </div>
          </div>
        </nav>
        {/* Mobile menu */}
        {isMobileMenuOpen && (
          <div className="lg:hidden bg-shell border-b border-zinc-200">
            <div className="space-y-1 px-4 pb-3 pt-2">
              {navigation.map((link) => (
                <Link
                  key={link.name}
                  to={link.href}
                  className={cn(
                    "block rounded-md px-3 py-2 text-base font-medium",
                    isActive(link.href) ? "bg-zinc-50 text-zinc-900" : "text-zinc-500 hover:bg-zinc-50 hover:text-zinc-900"
                  )}
                  onClick={() => setIsMobileMenuOpen(false)}
                >
                  <div className="flex items-center gap-3">
                    <link.icon className="w-5 h-5" />
                    {link.name}
                    {link.liveIndicator ? (
                      <span className="ml-auto inline-flex items-center rounded-full border border-emerald-200 bg-emerald-50 px-2 py-0.5 text-[10px] font-semibold uppercase tracking-[0.12em] text-emerald-700">
                        <span className="mr-1 inline-block h-1.5 w-1.5 rounded-full bg-emerald-500" />
                        Live
                      </span>
                    ) : null}
                  </div>
                </Link>
              ))}
              <Link
                to="/pricing"
                className="block rounded-md px-3 py-2 text-base font-medium text-zinc-900 hover:bg-zinc-50"
                onClick={() => setIsMobileMenuOpen(false)}
              >
                <div className="flex items-center gap-3">
                  <DollarSign className="w-5 h-5" />
                  Pricing
                </div>
              </Link>
              <Link
                to="/partners?requested=production"
                className="block rounded-md px-3 py-2 text-base font-medium text-zinc-900 hover:bg-zinc-50"
                onClick={() => setIsMobileMenuOpen(false)}
              >
                <div className="flex items-center gap-3">
                  <Users className="w-5 h-5" />
                  Talk to Us
                </div>
              </Link>
              <Link
                to="/dashboard"
                className="block rounded-md px-3 py-2 text-base font-medium text-zinc-900 hover:bg-zinc-50"
                onClick={() => setIsMobileMenuOpen(false)}
              >
                <div className="flex items-center gap-3">
                  <LayoutDashboard className="w-5 h-5" />
                  Dashboard
                </div>
              </Link>
            </div>
          </div>
        )}
      </header>

      <main className="relative z-10 flex-1">
        <Outlet />
      </main>

      <footer className="relative z-10 bg-shell border-t border-zinc-200 py-12">
        <div className="mx-auto max-w-7xl px-4 sm:px-6 lg:px-8">
          <div className="flex flex-col gap-6 md:flex-row md:items-start md:justify-between">
            <div className="flex items-center gap-2 md:pt-1">
              <img src="/brand-mark.svg" alt="Oxidity logo" className="h-5 w-5 rounded" />
              <span className="text-zinc-500 font-medium">Oxidity</span>
            </div>
            <div className="flex flex-wrap justify-center gap-x-6 gap-y-3 text-sm text-zinc-500 md:max-w-3xl md:justify-start">
              <Link to="/proof" className="hover:text-zinc-900">Proof</Link>
              <Link to="/how-it-works" className="hover:text-zinc-900">How it Works</Link>
              <Link to="/private-ethereum-rpc" className="hover:text-zinc-900">Private RPC</Link>
              <Link to="/developers" className="hover:text-zinc-900">Developers</Link>
              <Link to="/pricing" className="hover:text-zinc-900">Pricing</Link>
              <Link to="/partners" className="hover:text-zinc-900">Teams</Link>
              <Link to="/mev-protection" className="hover:text-zinc-900">MEV Protection</Link>
              <Link to="/risk-policy" className="hover:text-zinc-900">Risk Policy</Link>
              <Link to="/status" className="hover:text-zinc-900">Status</Link>
              <Link to="/terms" className="hover:text-zinc-900">Terms</Link>
            </div>
            <div className="text-sm text-zinc-400 md:text-right">
              &copy; {new Date().getFullYear()} Oxidity.io. All rights reserved.
            </div>
          </div>
        </div>
      </footer>
    </div>
  );
}
