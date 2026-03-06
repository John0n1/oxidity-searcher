import { Outlet, Link, useLocation } from 'react-router-dom';
import { Shield, Activity, Code, LayoutDashboard, Users, FileText, Menu, Moon, Sun, X } from 'lucide-react';
import { useEffect, useState } from 'react';
import { clsx, type ClassValue } from 'clsx';
import { twMerge } from 'tailwind-merge';
import { applySeo } from '../lib/seo';

const THEME_STORAGE_KEY = 'mitander.theme';

export function cn(...inputs: ClassValue[]) {
  return twMerge(clsx(inputs));
}

export function Layout() {
  const [isMobileMenuOpen, setIsMobileMenuOpen] = useState(false);
  const [theme, setTheme] = useState<'light' | 'dark'>(() => {
    if (typeof window === 'undefined') {
      return 'dark';
    }
    const stored = window.localStorage.getItem(THEME_STORAGE_KEY);
    if (stored === 'light' || stored === 'dark') {
      return stored;
    }
    return 'dark';
  });
  const location = useLocation();

  useEffect(() => {
    applySeo(location.pathname);
  }, [location.pathname]);

  useEffect(() => {
    const root = document.documentElement;
    const dark = theme === 'dark';
    root.classList.toggle('theme-dark', dark);
    root.style.colorScheme = dark ? 'dark' : 'light';
    window.localStorage.setItem(THEME_STORAGE_KEY, theme);
  }, [theme]);

  const navigation = [
    { name: 'MEV Protection', href: '/mev-protection', icon: Shield },
    { name: 'Private RPC', href: '/private-ethereum-rpc', icon: Code },
    { name: 'How it Works', href: '/how-it-works', icon: Shield },
    { name: 'Developers', href: '/developers', icon: Code },
    { name: 'Partners', href: '/partners', icon: Users },
    { name: 'Risk Policy', href: '/risk-policy', icon: FileText },
    { name: 'Status', href: '/status', icon: Activity },
  ];

  const isActive = (path: string) => location.pathname === path;
  const toggleTheme = () => setTheme((current) => (current === 'dark' ? 'light' : 'dark'));

  return (
    <div className="relative min-h-screen bg-page text-zinc-900 font-sans flex flex-col overflow-x-hidden">
      <div className="starscape" aria-hidden="true">
        <div className="bg-aura" />
        <div className="bg-wave" />
        <div className="bg-wave bg-wave-2" />
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
                <img src="/brand-mark.svg" alt="Mitander logo" className="h-8 w-8 rounded-lg" />
                <div className="leading-none">
                  <span className="block text-xl font-semibold tracking-tight">Mitander</span>
                  <span className="block text-[11px] font-medium uppercase tracking-[0.16em] text-zinc-500">Private Execution</span>
                </div>
              </Link>
              <div className="hidden ml-10 space-x-8 lg:block">
                {navigation.map((link) => (
                  <Link
                    key={link.name}
                    to={link.href}
                    className={cn(
                      "text-sm font-medium transition-colors hover:text-zinc-900",
                      isActive(link.href) ? "text-zinc-900" : "text-zinc-500"
                    )}
                  >
                    {link.name}
                  </Link>
                ))}
              </div>
            </div>
            <div className="hidden lg:flex items-center gap-4">
              <div className="flex items-center gap-2 px-3 py-1.5 bg-emerald-50 text-emerald-700 rounded-full text-xs font-medium border border-emerald-200">
                <div className="w-2 h-2 rounded-full bg-emerald-500 animate-pulse" />
                RPC Operational
              </div>
              <Link
                to="/dashboard"
                className="flex items-center gap-2 bg-zinc-900 text-white px-4 py-2 rounded-lg text-sm font-medium hover:bg-zinc-800 transition-colors"
              >
                <LayoutDashboard className="w-4 h-4" />
                Dashboard
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
        <div className="hidden lg:block absolute right-6 top-full mt-2">
          <button
            type="button"
            onClick={toggleTheme}
            className="inline-flex items-center gap-2 rounded-full border border-zinc-300 bg-white px-3 py-1.5 text-xs font-medium text-zinc-700 shadow-sm hover:bg-zinc-50"
            aria-label={theme === 'dark' ? 'Switch to light theme' : 'Switch to dark theme'}
          >
            {theme === 'dark' ? <Sun className="h-4 w-4" /> : <Moon className="h-4 w-4" />}
            {theme === 'dark' ? 'Light' : 'Dark'}
          </button>
        </div>
        {/* Mobile menu */}
        {isMobileMenuOpen && (
          <div className="lg:hidden bg-shell border-b border-zinc-200">
            <div className="space-y-1 px-4 pb-3 pt-2">
              <button
                type="button"
                onClick={toggleTheme}
                className="mb-2 inline-flex items-center gap-2 rounded-md border border-zinc-300 bg-white px-3 py-2 text-sm font-medium text-zinc-700 hover:bg-zinc-50"
              >
                {theme === 'dark' ? <Sun className="h-4 w-4" /> : <Moon className="h-4 w-4" />}
                {theme === 'dark' ? 'Light theme' : 'Dark theme'}
              </button>
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
                  </div>
                </Link>
              ))}
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
          <div className="flex flex-col md:flex-row justify-between items-center gap-6">
            <div className="flex items-center gap-2">
              <img src="/brand-mark.svg" alt="Mitander logo" className="h-5 w-5 rounded" />
              <span className="text-zinc-500 font-medium">Mitander</span>
            </div>
            <div className="flex gap-6 text-sm text-zinc-500">
              <Link to="/how-it-works" className="hover:text-zinc-900">How it Works</Link>
              <Link to="/private-ethereum-rpc" className="hover:text-zinc-900">Private RPC</Link>
              <Link to="/gasless-ethereum-transactions" className="hover:text-zinc-900">Gasless</Link>
              <Link to="/mev-protection" className="hover:text-zinc-900">MEV Protection</Link>
              <Link to="/developers" className="hover:text-zinc-900">Developers</Link>
              <Link to="/risk-policy" className="hover:text-zinc-900">Risk Policy</Link>
              <Link to="/terms" className="hover:text-zinc-900">Terms</Link>
            </div>
            <div className="text-sm text-zinc-400">
              &copy; {new Date().getFullYear()} Mitander.dev. All rights reserved.
            </div>
          </div>
        </div>
      </footer>
    </div>
  );
}
