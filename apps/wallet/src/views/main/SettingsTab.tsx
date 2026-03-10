import { useEffect, useState } from 'react';
import { AnimatePresence, motion } from 'motion/react';
import { Capacitor } from '@capacitor/core';
import {
  Bell,
  ChevronRight,
  FileText,
  Fingerprint,
  HelpCircle,
  KeyRound,
  LogOut,
  Moon,
  Palette,
  Shield,
  ShieldAlert,
  Smartphone,
  Users,
  Wallet,
  X,
} from 'lucide-react';

import { Logo } from '../../components/Logo';
import { WALLET_AVATAR_OPTIONS, WalletAvatar } from '../../components/WalletAvatar';
import { copyText } from '../../lib/clipboard';
import { applyThemeMode, readThemeMode, type ThemeMode } from '../../lib/theme';
import { useAppStore } from '../../store/appStore';
import { cn } from '../../utils/cn';

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
  const setAccountAvatar = useAppStore((state) => state.setAccountAvatar);
  const setView = useAppStore((state) => state.setView);

  const [isAvatarPickerOpen, setIsAvatarPickerOpen] = useState(false);
  const [notificationsEnabled, setNotificationsEnabled] = useState<boolean>(() => {
    if (typeof window === 'undefined') {
      return true;
    }
    const value = window.localStorage.getItem('oxidity.notifications.enabled');
    return value !== 'false';
  });
  const [themeMode, setThemeMode] = useState<ThemeMode>(() => readThemeMode());

  useEffect(() => {
    if (typeof window === 'undefined') {
      return;
    }
    window.localStorage.setItem('oxidity.notifications.enabled', notificationsEnabled ? 'true' : 'false');
  }, [notificationsEnabled]);

  useEffect(() => {
    applyThemeMode(themeMode);
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

  const handleManageWallets = () => {
    useAppStore.getState().setTab('home');
  };

  const sections = [
    {
      title: 'Wallet',
      items: [
        {
          icon: Wallet,
          label: 'Manage Wallets',
          value: `${accounts.length} Wallet${accounts.length > 1 ? 's' : ''}`,
          onClick: handleManageWallets,
        },
        {
          icon: Users,
          label: 'Address List',
          value: `${addressBook.length} Saved`,
          onClick: () => setView('address-book'),
        },
        {
          icon: Palette,
          label: 'Wallet Icon',
          value: activeAccount ? 'Customize' : '',
          onClick: () => setIsAvatarPickerOpen(true),
        },
        {
          icon: Smartphone,
          label: 'Connected Apps',
          value: '0 Apps',
          onClick: handleConnectedApps,
        },
        {
          icon: ShieldAlert,
          label: 'Advanced Settings',
          value: '',
          onClick: () => setView('advanced'),
        },
      ],
    },
    {
      title: 'Security',
      items: [
        {
          icon: KeyRound,
          label: 'Recovery Phrase',
          value: '',
          warning: true,
          onClick: () => setView('advanced'),
        },
        {
          icon: Shield,
          label: 'App Security',
          value: 'Passcode',
          onClick: () => setView('advanced'),
        },
        {
          icon: Fingerprint,
          label: 'Biometrics',
          value: biometricsEnabled ? 'On' : 'Off',
          onClick: () => setBiometricsEnabled(!biometricsEnabled),
        },
      ],
    },
    {
      title: 'Preferences',
      items: [
        {
          icon: Bell,
          label: 'Notifications',
          value: notificationsEnabled ? 'On' : 'Off',
          onClick: () => setNotificationsEnabled((current) => !current),
        },
        {
          icon: Moon,
          label: 'Change Theme',
          value: themeMode === 'midnight' ? 'Midnight' : 'Dark',
          onClick: () => setThemeMode((current) => (current === 'dark' ? 'midnight' : 'dark')),
        },
      ],
    },
    {
      title: 'About',
      items: [
        { icon: HelpCircle, label: 'Help & Support', value: '', onClick: () => setView('support') },
        { icon: FileText, label: 'Legal & Privacy', value: '', onClick: () => setView('legal') },
      ],
    },
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
      <div className="sticky top-0 z-10 flex items-center justify-between border-b border-white/5 bg-zinc-950/80 p-6 pb-4 backdrop-blur-xl">
        <h2 className="text-2xl font-semibold tracking-tight">Settings</h2>
      </div>

      <div className="space-y-8 px-6 py-4">
        <div className="flex items-center gap-4 overflow-hidden rounded-3xl border border-white/5 bg-zinc-900 p-5">
          <WalletAvatar avatarId={activeAccount?.avatarId} className="h-14 w-14 border-2 border-zinc-950" />
          <div className="min-w-0 flex-1">
            <h3 className="mb-0.5 text-lg font-semibold">{activeAccount?.name || 'Main Wallet'}</h3>
            <p className="block max-w-full overflow-hidden text-ellipsis whitespace-nowrap font-mono text-sm text-zinc-500">
              {formatDisplayAddress(activeAccount?.address)}
            </p>
          </div>
          <div className="flex shrink-0 gap-2">
            <button
              onClick={() => setIsAvatarPickerOpen(true)}
              className="rounded-full bg-zinc-800 px-4 py-2 text-sm font-medium transition-colors hover:bg-zinc-700"
            >
              Icon
            </button>
            <button
              onClick={() => void handleCopyAddress()}
              className="rounded-full bg-zinc-800 px-4 py-2 text-sm font-medium transition-colors hover:bg-zinc-700"
            >
              Copy
            </button>
          </div>
        </div>

        {sections.map((section, index) => (
          <div key={index}>
            <h4 className="mb-3 px-2 text-sm font-medium uppercase tracking-wider text-zinc-500">
              {section.title}
            </h4>
            <div className="overflow-hidden rounded-3xl border border-white/5 bg-zinc-900">
              {section.items.map((item, itemIndex) => (
                <button
                  key={itemIndex}
                  onClick={item.onClick}
                  className={cn(
                    'flex w-full items-center justify-between gap-3 p-4 text-left transition-colors hover:bg-zinc-800',
                    itemIndex !== section.items.length - 1 && 'border-b border-white/5',
                  )}
                >
                  <div className="flex min-w-0 items-center gap-3">
                    <div
                      className={cn(
                        'flex h-8 w-8 items-center justify-center rounded-xl',
                        item.warning ? 'bg-red-500/10' : 'bg-zinc-800',
                      )}
                    >
                      <item.icon
                        className={cn('h-4 w-4', item.warning ? 'text-red-400' : 'text-zinc-400')}
                      />
                    </div>
                    <span
                      className={cn(
                        'block truncate font-medium',
                        item.warning ? 'text-red-400' : 'text-white',
                      )}
                    >
                      {item.label}
                    </span>
                  </div>
                  <div className="flex shrink-0 items-center gap-2">
                    {item.value ? (
                      <span className="text-sm font-medium text-zinc-500">{item.value}</span>
                    ) : null}
                    <ChevronRight className="h-4 w-4 text-zinc-600" />
                  </div>
                </button>
              ))}
            </div>
          </div>
        ))}

        <button
          onClick={() => useAppStore.getState().setIsLocked(true)}
          className="flex w-full items-center justify-center gap-2 rounded-2xl border border-white/5 bg-zinc-900 py-4 font-medium text-red-400 transition-colors hover:bg-red-500/10"
        >
          <LogOut className="h-4 w-4" />
          Lock Wallet
        </button>

        <button
          onClick={() => setView('licenses')}
          className="flex w-full items-center justify-between rounded-2xl border border-white/5 bg-zinc-900 px-5 py-4 text-left transition-colors hover:bg-zinc-800"
        >
          <div>
            <div className="font-medium text-white">Open Source Licenses</div>
            <div className="text-sm text-zinc-500">Review licenses for bundled packages</div>
          </div>
          <ChevronRight className="h-4 w-4 text-zinc-600" />
        </button>

        <div className="flex flex-col items-center justify-center gap-4 pt-8 pb-4 text-center">
          <Logo className="h-8 w-8 text-zinc-700" />
          <p className="text-[10px] uppercase tracking-[0.2em] text-zinc-600">
            Oxidity Wallet v{__OXIDITY_WALLET_VERSION__}
          </p>
        </div>
      </div>

      <AnimatePresence>
        {isAvatarPickerOpen && activeAccount ? (
          <>
            <motion.button
              initial={{ opacity: 0 }}
              animate={{ opacity: 1 }}
              exit={{ opacity: 0 }}
              onClick={() => setIsAvatarPickerOpen(false)}
              className="fixed inset-0 z-50 bg-black/60 backdrop-blur-sm"
              aria-label="Close wallet icon picker"
            />
            <motion.div
              initial={{ opacity: 0, y: 80 }}
              animate={{ opacity: 1, y: 0 }}
              exit={{ opacity: 0, y: 80 }}
              className="fixed bottom-0 left-0 right-0 z-[51] max-h-[80vh] overflow-y-auto rounded-t-[40px] border-t border-white/10 bg-zinc-950 p-6"
            >
              <div className="mb-6 flex items-center justify-between">
                <div>
                  <h3 className="text-xl font-semibold">Choose Wallet Icon</h3>
                  <p className="text-sm text-zinc-500">Predefined icons use the open source Lucide set.</p>
                </div>
                <button
                  onClick={() => setIsAvatarPickerOpen(false)}
                  className="rounded-full bg-zinc-900 p-2 text-zinc-400 transition-colors hover:text-white"
                >
                  <X className="h-5 w-5" />
                </button>
              </div>

              <div className="grid grid-cols-2 gap-3">
                {WALLET_AVATAR_OPTIONS.map((option) => {
                  const isSelected = activeAccount.avatarId === option.id;
                  return (
                    <button
                      key={option.id}
                      onClick={() => {
                        setAccountAvatar(activeAccount.id, option.id);
                        setIsAvatarPickerOpen(false);
                      }}
                      className={cn(
                        'flex items-center gap-4 rounded-2xl border p-4 text-left transition-colors',
                        isSelected
                          ? 'border-indigo-500/40 bg-indigo-500/10'
                          : 'border-white/5 bg-zinc-900 hover:bg-zinc-800',
                      )}
                    >
                      <WalletAvatar avatarId={option.id} className="h-12 w-12" />
                      <div>
                        <div className="font-medium text-white">{option.label}</div>
                        <div className="text-xs text-zinc-500">
                          {isSelected ? 'Current wallet icon' : 'Tap to select'}
                        </div>
                      </div>
                    </button>
                  );
                })}
              </div>
            </motion.div>
          </>
        ) : null}
      </AnimatePresence>
    </ScreenWrapper>
  );
}
