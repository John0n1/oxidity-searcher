import { useEffect, useState } from 'react';
import { Capacitor } from '@capacitor/core';
import { motion } from 'motion/react';
import { Shield, KeyRound, Bell, Smartphone, Moon, HelpCircle, FileText, ChevronRight, Wallet, LogOut, Fingerprint, ShieldAlert, Users } from 'lucide-react';
import { cn } from '../../utils/cn';
import { useAppStore } from '../../store/appStore';
import { Logo } from '../../components/Logo';
import { copyText } from '../../lib/clipboard';

function formatDisplayAddress(address?: string): string {
  if (!address) {
    return '0x1234...5678';
  }
  return `${address.slice(0, 8)}...${address.slice(-6)}`;
}

export function SettingsTab() {
  const isNativePlatform = Capacitor.isNativePlatform();
  const ScreenWrapper: any = isNativePlatform ? 'div' : motion.div;
  const biometricsEnabled = useAppStore((state) => state.biometricsEnabled);
  const setBiometricsEnabled = useAppStore((state) => state.setBiometricsEnabled);
  const activeAccountId = useAppStore((state) => state.activeAccountId);
  const accounts = useAppStore((state) => state.accounts);
  const activeAccount = accounts.find((account) => account.id === activeAccountId);
  const addressBook = useAppStore((state) => state.addressBook);

  const setView = useAppStore((state) => state.setView);
  const [notificationsEnabled, setNotificationsEnabled] = useState<boolean>(() => {
    if (typeof window === 'undefined') {
      return true;
    }
    const value = window.localStorage.getItem('oxidity.notifications.enabled');
    return value !== 'false';
  });
  const [themeMode, setThemeMode] = useState<'dark' | 'midnight'>(() => {
    if (typeof window === 'undefined') {
      return 'dark';
    }
    return window.localStorage.getItem('oxidity.theme.mode') === 'midnight' ? 'midnight' : 'dark';
  });

  useEffect(() => {
    if (typeof window === 'undefined') {
      return;
    }
    window.localStorage.setItem('oxidity.notifications.enabled', notificationsEnabled ? 'true' : 'false');
  }, [notificationsEnabled]);

  useEffect(() => {
    if (typeof document === 'undefined') {
      return;
    }
    document.documentElement.dataset.oxidityTheme = themeMode;
    window.localStorage.setItem('oxidity.theme.mode', themeMode);
  }, [themeMode]);

  const handleCopyAddress = async () => {
    if (!activeAccount?.address) {
      return;
    }
    await copyText(activeAccount.address);
  };

  const handleConnectedApps = () => {
    useAppStore.getState().setTab('activity');
  };

  const handleRecoveryPhrase = () => {
    setView('advanced');
  };

  const handleAppSecurity = () => {
    setView('advanced');
  };

  const handleManageWallets = () => {
    useAppStore.getState().setTab('home');
  };

  const handleNotifications = () => {
    setNotificationsEnabled((current) => !current);
  };

  const handleThemeToggle = () => {
    setThemeMode((current) => (current === 'dark' ? 'midnight' : 'dark'));
  };

  const SECTIONS = [
    {
      title: 'Wallet',
      items: [
        {
          icon: Wallet,
          label: 'Manage Wallets',
          value: `${accounts.length} Wallet${accounts.length > 1 ? 's' : ''}`,
          onClick: handleManageWallets,
        },
        { icon: Users, label: 'Address List', value: `${addressBook.length} Saved`, onClick: () => setView('address-book') },
        { icon: Smartphone, label: 'Connected Apps', value: '0 Apps', onClick: handleConnectedApps },
        { icon: ShieldAlert, label: 'Advanced Settings', value: '', onClick: () => setView('advanced') },
      ]
    },
    {
      title: 'Security',
      items: [
        { icon: KeyRound, label: 'Recovery Phrase', value: '', warning: true, onClick: handleRecoveryPhrase },
        { icon: Shield, label: 'App Security', value: 'Passcode', onClick: handleAppSecurity },
        { 
          icon: Fingerprint, 
          label: 'Biometrics', 
          value: biometricsEnabled ? 'On' : 'Off',
          onClick: () => setBiometricsEnabled(!biometricsEnabled)
        },
      ]
    },
    {
      title: 'Preferences',
      items: [
        { icon: Bell, label: 'Notifications', value: notificationsEnabled ? 'On' : 'Off', onClick: handleNotifications },
        { icon: Moon, label: 'Theme', value: themeMode === 'midnight' ? 'Midnight' : 'Dark', onClick: handleThemeToggle },
      ]
    },
    {
      title: 'About',
      items: [
        { icon: HelpCircle, label: 'Help & Support', value: '', onClick: () => setView('support') },
        { icon: FileText, label: 'Legal & Privacy', value: '', onClick: () => setView('legal') },
      ]
    }
  ];

  return (
    <ScreenWrapper
      {...(!isNativePlatform
        ? {
            initial: { opacity: 0, y: 10 },
            animate: { opacity: 1, y: 0 },
            exit: { opacity: 0, y: -10 },
            transition: { duration: 0.3 },
          }
        : {})}
      className="absolute inset-0 overflow-x-hidden overflow-y-auto overscroll-y-contain pb-24"
    >
      {/* Header */}
      <div className="flex items-center justify-between p-6 pb-4 sticky top-0 bg-zinc-950/80 backdrop-blur-xl z-10 border-b border-white/5">
        <h2 className="text-2xl font-semibold tracking-tight">Settings</h2>
      </div>

      <div className="px-6 py-4 space-y-8">
        {/* Profile / Wallet Summary */}
        <div className="flex items-center gap-4 overflow-hidden bg-zinc-900 border border-white/5 rounded-3xl p-5">
          <div className="w-14 h-14 rounded-full bg-gradient-to-tr from-indigo-500 to-purple-500 flex items-center justify-center border-2 border-zinc-950 shadow-lg" />
          <div className="min-w-0 flex-1">
            <h3 className="font-semibold text-lg mb-0.5">{activeAccount?.name || 'Main Wallet'}</h3>
            <p className="block max-w-full overflow-hidden text-ellipsis whitespace-nowrap text-sm text-zinc-500 font-mono">
              {formatDisplayAddress(activeAccount?.address)}
            </p>
          </div>
          <button
            onClick={() => void handleCopyAddress()}
            className="shrink-0 bg-zinc-800 hover:bg-zinc-700 transition-colors px-4 py-2 rounded-full text-sm font-medium"
          >
            Copy
          </button>
        </div>

        {/* Sections */}
        {SECTIONS.map((section, i) => (
          <div key={i}>
            <h4 className="text-sm font-medium text-zinc-500 uppercase tracking-wider mb-3 px-2">
              {section.title}
            </h4>
            <div className="bg-zinc-900 border border-white/5 rounded-3xl overflow-hidden">
              {section.items.map((item, j) => (
                <button
                  key={j}
                  onClick={item.onClick}
                  className={cn(
                    "w-full flex items-center justify-between gap-3 p-4 text-left hover:bg-zinc-800 transition-colors",
                    j !== section.items.length - 1 && "border-b border-white/5"
                  )}
                >
                  <div className="flex min-w-0 items-center gap-3">
                    <div className={cn(
                      "w-8 h-8 rounded-xl flex items-center justify-center",
                      item.warning ? "bg-red-500/10" : "bg-zinc-800"
                    )}>
                      <item.icon className={cn(
                        "w-4 h-4",
                        item.warning ? "text-red-400" : "text-zinc-400"
                      )} />
                    </div>
                    <div className="min-w-0">
                      <span className={cn(
                        "block truncate font-medium",
                        item.warning ? "text-red-400" : "text-white"
                      )}>
                        {item.label}
                      </span>
                    </div>
                  </div>
                  <div className="flex shrink-0 items-center gap-2">
                    {item.value && (
                      <span className="text-sm text-zinc-500 font-medium">{item.value}</span>
                    )}
                    <ChevronRight className="w-4 h-4 text-zinc-600" />
                  </div>
                </button>
              ))}
            </div>
          </div>
        ))}

        {/* Lock Wallet */}
        <button 
          onClick={() => {
            useAppStore.getState().setIsLocked(true);
          }}
          className="w-full flex items-center justify-center gap-2 bg-zinc-900 border border-white/5 text-red-400 font-medium py-4 rounded-2xl hover:bg-red-500/10 transition-colors"
        >
          <LogOut className="w-4 h-4" />
          Lock Wallet
        </button>

        <div className="pt-8 pb-4 flex flex-col items-center justify-center gap-4 text-center">
          <Logo className="w-8 h-8 text-zinc-700" />
          <p className="text-[10px] text-zinc-600 uppercase tracking-[0.2em]">
            Oxidity Wallet v1.0.0
          </p>
        </div>
      </div>
    </ScreenWrapper>
  );
}
