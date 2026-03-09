import { useEffect, useMemo, useState, type ReactNode } from 'react';
import { motion } from 'motion/react';
import {
  AlertTriangle,
  ArrowLeft,
  ChevronRight,
  Copy,
  Cpu,
  Database,
  EyeOff,
  Key,
  Lock,
  RefreshCw,
  ShieldAlert,
  Trash2,
} from 'lucide-react';

import { checkBiometrics } from '../lib/nativeAuth';
import { useAppStore } from '../store/appStore';
import { cn } from '../utils/cn';
import { Logo } from '../components/Logo';
import { copyText } from '../lib/clipboard';

type SectionItem = {
  icon: typeof ShieldAlert;
  label: string;
  value?: string;
  color?: string;
  onClick?: () => void;
};

function formatAccountAddress(address?: string): string {
  if (!address) {
    return '';
  }
  return `${address.slice(0, 8)}...${address.slice(-6)}`;
}

function MaskedSecret({ value }: { value: string }) {
  return (
    <p className="rounded-xl border border-white/5 bg-black/40 p-3 font-mono text-xs leading-relaxed text-zinc-300 break-all">
      {value}
    </p>
  );
}

function SectionRow({
  item,
  children,
}: {
  item: SectionItem;
  children?: ReactNode;
}) {
  if (!item.onClick) {
    return (
      <div className="flex items-center justify-between gap-3 p-5">
        <div className="flex min-w-0 items-center gap-3">
          <div className="flex h-8 w-8 items-center justify-center rounded-xl bg-zinc-800">
            <item.icon className={cn('h-4 w-4', item.color)} />
          </div>
          <span className={cn('truncate text-sm font-medium', item.color)}>{item.label}</span>
        </div>
        <div className="flex shrink-0 items-center gap-2">
          {item.value ? <span className="text-xs font-medium text-zinc-500">{item.value}</span> : null}
          {children}
        </div>
      </div>
    );
  }

  return (
    <button
      onClick={item.onClick}
      className="flex w-full items-center justify-between gap-3 p-5 text-left transition-colors hover:bg-zinc-800"
    >
      <div className="flex min-w-0 items-center gap-3">
        <div className="flex h-8 w-8 items-center justify-center rounded-xl bg-zinc-800">
          <item.icon className={cn('h-4 w-4', item.color)} />
        </div>
        <span className={cn('truncate text-sm font-medium', item.color)}>{item.label}</span>
      </div>
      <div className="flex shrink-0 items-center gap-2">
        {item.value ? <span className="text-xs font-medium text-zinc-500">{item.value}</span> : null}
        {children || <ChevronRight className="h-4 w-4 text-zinc-600" />}
      </div>
    </button>
  );
}

export function AdvancedSettingsView() {
  const setView = useAppStore((state) => state.setView);
  const exportActivePrivateKey = useAppStore((state) => state.exportActivePrivateKey);
  const exportActiveRecoveryPhrase = useAppStore((state) => state.exportActiveRecoveryPhrase);
  const changePasscode = useAppStore((state) => state.changePasscode);
  const removeActiveAccount = useAppStore((state) => state.removeActiveAccount);
  const refreshWalletData = useAppStore((state) => state.refreshWalletData);
  const activeAccountId = useAppStore((state) => state.activeAccountId);
  const accounts = useAppStore((state) => state.accounts);
  const activeAccount = accounts.find((account) => account.id === activeAccountId);

  const [showPrivateKey, setShowPrivateKey] = useState(false);
  const [privateKey, setPrivateKey] = useState('');
  const [showRecoveryPhrase, setShowRecoveryPhrase] = useState(false);
  const [recoveryPhrase, setRecoveryPhrase] = useState('');
  const [isLoadingPrivateKey, setIsLoadingPrivateKey] = useState(false);
  const [isLoadingRecoveryPhrase, setIsLoadingRecoveryPhrase] = useState(false);
  const [showPasscodeSheet, setShowPasscodeSheet] = useState(false);
  const [currentPasscode, setCurrentPasscode] = useState('');
  const [nextPasscode, setNextPasscode] = useState('');
  const [confirmPasscode, setConfirmPasscode] = useState('');
  const [isChangingPasscode, setIsChangingPasscode] = useState(false);
  const [isClearingCache, setIsClearingCache] = useState(false);
  const [isResyncing, setIsResyncing] = useState(false);
  const [errorMessage, setErrorMessage] = useState<string | null>(null);
  const [statusMessage, setStatusMessage] = useState<string | null>(null);
  const [hardwareStatus, setHardwareStatus] = useState('Checking…');
  const [hardwareStatusColor, setHardwareStatusColor] = useState('text-zinc-500');
  const [showEncryptionDetails, setShowEncryptionDetails] = useState(false);

  const localDatabaseKb = useMemo(
    () =>
      Math.max(
        1,
        Math.round(new Blob([localStorage.getItem('oxidity_wallet_vault_v2') || '']).size / 1024),
      ),
    [],
  );

  const refreshHardwareStatus = async () => {
    const result = await checkBiometrics();
    if (!result) {
      setHardwareStatus('Browser vault');
      setHardwareStatusColor('text-zinc-400');
      return;
    }
    if (result.isAvailable) {
      setHardwareStatus('Fingerprint ready');
      setHardwareStatusColor('text-emerald-400');
      return;
    }
    if (result.deviceIsSecure) {
      setHardwareStatus('Device secure');
      setHardwareStatusColor('text-amber-400');
      return;
    }
    setHardwareStatus('Unavailable');
    setHardwareStatusColor('text-red-400');
  };

  useEffect(() => {
    void refreshHardwareStatus();
  }, []);

  const handleTogglePrivateKey = async () => {
    if (showPrivateKey) {
      setShowPrivateKey(false);
      return;
    }

    setIsLoadingPrivateKey(true);
    setErrorMessage(null);
    setStatusMessage(null);
    try {
      const key = await exportActivePrivateKey();
      setPrivateKey(key);
      setShowPrivateKey(true);
    } catch (error) {
      setErrorMessage(error instanceof Error ? error.message : 'Failed to load private key');
    } finally {
      setIsLoadingPrivateKey(false);
    }
  };

  const handleToggleRecoveryPhrase = async () => {
    if (showRecoveryPhrase) {
      setShowRecoveryPhrase(false);
      return;
    }

    setIsLoadingRecoveryPhrase(true);
    setErrorMessage(null);
    setStatusMessage(null);
    try {
      const phrase = await exportActiveRecoveryPhrase();
      setRecoveryPhrase(phrase);
      setShowRecoveryPhrase(true);
    } catch (error) {
      setErrorMessage(error instanceof Error ? error.message : 'Failed to load recovery phrase');
    } finally {
      setIsLoadingRecoveryPhrase(false);
    }
  };

  const handleCopy = async (value: string, successLabel: string) => {
    if (!value) {
      return;
    }
    await copyText(value);
    setStatusMessage(successLabel);
    setErrorMessage(null);
  };

  const handleChangePasscode = async () => {
    if (!/^\d{6}$/.test(currentPasscode)) {
      setErrorMessage('Current passcode must be 6 digits');
      return;
    }
    if (!/^\d{6}$/.test(nextPasscode)) {
      setErrorMessage('New passcode must be 6 digits');
      return;
    }
    if (nextPasscode !== confirmPasscode) {
      setErrorMessage('New passcodes do not match');
      return;
    }

    setIsChangingPasscode(true);
    setErrorMessage(null);
    setStatusMessage(null);
    try {
      await changePasscode(currentPasscode, nextPasscode);
      setStatusMessage('Passcode updated');
      setShowPasscodeSheet(false);
      setCurrentPasscode('');
      setNextPasscode('');
      setConfirmPasscode('');
    } catch (error) {
      setErrorMessage(error instanceof Error ? error.message : 'Failed to update passcode');
    } finally {
      setIsChangingPasscode(false);
    }
  };

  const handleClearCache = async () => {
    setIsClearingCache(true);
    setErrorMessage(null);
    setStatusMessage(null);
    try {
      localStorage.removeItem('oxidity.notifications.enabled');
      localStorage.removeItem('oxidity.theme.mode');
      document.documentElement.dataset.oxidityTheme = 'dark';
      await refreshWalletData();
      setStatusMessage('Local UI cache cleared');
    } catch (error) {
      setErrorMessage(error instanceof Error ? error.message : 'Failed to clear cache');
    } finally {
      setIsClearingCache(false);
    }
  };

  const handleResyncWallet = async () => {
    setIsResyncing(true);
    setErrorMessage(null);
    setStatusMessage(null);
    try {
      await refreshWalletData();
      setStatusMessage('Wallet data refreshed');
    } catch (error) {
      setErrorMessage(error instanceof Error ? error.message : 'Failed to refresh wallet data');
    } finally {
      setIsResyncing(false);
    }
  };

  const sections: Array<{ title: string; items: SectionItem[] }> = [
    {
      title: 'Security & Encryption',
      items: [
        {
          icon: Lock,
          label: 'Change Passcode',
          value: '6 digits',
          color: 'text-white',
          onClick: () => {
            setShowPasscodeSheet(true);
            setErrorMessage(null);
            setStatusMessage(null);
          },
        },
        {
          icon: ShieldAlert,
          label: 'Additional Encryption',
          value: 'AES-GCM + PBKDF2',
          color: 'text-indigo-400',
          onClick: () => setShowEncryptionDetails((current) => !current),
        },
        {
          icon: Cpu,
          label: 'Hardware Security Module',
          value: hardwareStatus,
          color: hardwareStatusColor,
          onClick: () => void refreshHardwareStatus(),
        },
      ],
    },
    {
      title: 'Data & Storage',
      items: [
        {
          icon: Database,
          label: 'Local Vault Size',
          value: `${localDatabaseKb} KB`,
          color: 'text-zinc-400',
        },
        {
          icon: RefreshCw,
          label: 'Resync Wallet Data',
          value: isResyncing ? 'Syncing…' : '',
          color: 'text-zinc-400',
          onClick: () => void handleResyncWallet(),
        },
        {
          icon: RefreshCw,
          label: 'Clear UI Cache',
          value: isClearingCache ? 'Clearing…' : '',
          color: 'text-zinc-400',
          onClick: () => void handleClearCache(),
        },
      ],
    },
    {
      title: 'Danger Zone',
      items: [
        {
          icon: Trash2,
          label: 'Remove Wallet',
          value: '',
          color: 'text-red-400',
          onClick: () => {
            if (confirm('Are you sure you want to remove this wallet? This action cannot be undone.')) {
              removeActiveAccount();
            }
          },
        },
      ],
    },
  ];

  return (
    <motion.div
      initial={{ x: '100%' }}
      animate={{ x: 0 }}
      exit={{ x: '100%' }}
      transition={{ type: 'spring', damping: 25, stiffness: 200 }}
      className="absolute inset-0 z-50 flex flex-col overflow-hidden bg-zinc-950"
    >
      <div className="sticky top-0 z-10 flex items-center gap-4 border-b border-white/5 bg-zinc-950/80 p-6 backdrop-blur-xl">
        <button
          onClick={() => setView('main')}
          className="flex h-10 w-10 items-center justify-center rounded-full bg-zinc-900 transition-colors hover:bg-zinc-800"
        >
          <ArrowLeft className="h-5 w-5" />
        </button>
        <div className="min-w-0">
          <h2 className="text-xl font-semibold">Advanced Settings</h2>
          <p className="truncate text-xs text-zinc-500 font-mono">
            {formatAccountAddress(activeAccount?.address)}
          </p>
        </div>
      </div>

      <div className="flex-1 overflow-x-hidden overflow-y-auto overscroll-y-contain p-6 pb-12">
        <div className="space-y-8">
          <div className="space-y-4">
            <h3 className="px-2 text-sm font-medium uppercase tracking-wider text-zinc-400">Wallet Access</h3>
            <div className="space-y-4 rounded-3xl border border-white/5 bg-zinc-900 p-5">
              <div className="space-y-4 rounded-2xl border border-white/5 bg-zinc-950/40 p-4">
                <div className="flex items-center justify-between gap-3">
                  <div className="flex min-w-0 items-center gap-3">
                    <div className="flex h-10 w-10 items-center justify-center rounded-xl bg-indigo-500/10">
                      <EyeOff className="h-5 w-5 text-indigo-400" />
                    </div>
                    <div className="min-w-0">
                      <span className="block text-sm font-semibold">Recovery Phrase</span>
                      <span className="text-[10px] text-zinc-500">Back this up offline before removing the wallet</span>
                    </div>
                  </div>
                  <button
                    onClick={() => void handleToggleRecoveryPhrase()}
                    className="shrink-0 rounded-full bg-zinc-800 px-4 py-2 text-xs font-medium transition-colors hover:bg-zinc-700 disabled:opacity-60"
                    disabled={isLoadingRecoveryPhrase || activeAccount?.secretType !== 'mnemonic'}
                  >
                    {activeAccount?.secretType !== 'mnemonic'
                      ? 'Unavailable'
                      : showRecoveryPhrase
                        ? 'Hide'
                        : isLoadingRecoveryPhrase
                          ? 'Loading…'
                          : 'Show'}
                  </button>
                </div>

                {showRecoveryPhrase ? (
                  <div className="space-y-3 rounded-2xl border border-amber-500/10 bg-amber-500/5 p-4">
                    <div className="flex items-center gap-2 text-amber-400">
                      <AlertTriangle className="h-4 w-4" />
                      <span className="text-[10px] font-bold uppercase tracking-widest">Do not share this</span>
                    </div>
                    <div className="grid grid-cols-2 gap-2">
                      {recoveryPhrase.split(' ').filter(Boolean).map((word, index) => (
                        <div key={`${word}-${index}`} className="rounded-xl border border-white/5 bg-black/30 px-3 py-2 text-sm text-zinc-300">
                          <span className="mr-2 text-zinc-500">{index + 1}.</span>
                          {word}
                        </div>
                      ))}
                    </div>
                    <button
                      onClick={() => void handleCopy(recoveryPhrase, 'Recovery phrase copied')}
                      className="flex w-full items-center justify-center gap-2 rounded-xl bg-amber-500/10 py-2 text-xs font-medium text-amber-300 transition-colors hover:bg-amber-500/20"
                    >
                      <Copy className="h-4 w-4" />
                      Copy Recovery Phrase
                    </button>
                  </div>
                ) : null}
              </div>

              <div className="space-y-4 rounded-2xl border border-white/5 bg-zinc-950/40 p-4">
                <div className="flex items-center justify-between gap-3">
                  <div className="flex min-w-0 items-center gap-3">
                    <div className="flex h-10 w-10 items-center justify-center rounded-xl bg-indigo-500/10">
                      <Key className="h-5 w-5 text-indigo-400" />
                    </div>
                    <div className="min-w-0">
                      <span className="block text-sm font-semibold">Private Key</span>
                      <span className="text-[10px] text-zinc-500">Never share this with anyone</span>
                    </div>
                  </div>
                  <button
                    onClick={() => void handleTogglePrivateKey()}
                    className="shrink-0 rounded-full bg-zinc-800 px-4 py-2 text-xs font-medium transition-colors hover:bg-zinc-700 disabled:opacity-60"
                    disabled={isLoadingPrivateKey}
                  >
                    {showPrivateKey ? 'Hide' : isLoadingPrivateKey ? 'Loading…' : 'Show'}
                  </button>
                </div>

                {showPrivateKey ? (
                  <div className="space-y-3 rounded-2xl border border-red-500/10 bg-red-500/5 p-4">
                    <div className="flex items-center gap-2 text-red-400">
                      <AlertTriangle className="h-4 w-4" />
                      <span className="text-[10px] font-bold uppercase tracking-widest">High risk secret</span>
                    </div>
                    <MaskedSecret value={privateKey} />
                    <button
                      onClick={() => void handleCopy(privateKey, 'Private key copied')}
                      className="flex w-full items-center justify-center gap-2 rounded-xl bg-red-500/10 py-2 text-xs font-medium text-red-300 transition-colors hover:bg-red-500/20"
                    >
                      <Copy className="h-4 w-4" />
                      Copy Private Key
                    </button>
                  </div>
                ) : null}
              </div>
            </div>
          </div>

          {showEncryptionDetails ? (
            <div className="rounded-3xl border border-indigo-500/10 bg-indigo-500/5 p-5 text-sm text-indigo-200/80">
              Wallet secrets are encrypted locally with AES-GCM and a PBKDF2-derived key before being persisted in the vault. The encryption material never leaves the device.
            </div>
          ) : null}

          {errorMessage ? <p className="text-sm text-red-400">{errorMessage}</p> : null}
          {statusMessage ? <p className="text-sm text-emerald-400">{statusMessage}</p> : null}

          {sections.map((section) => (
            <div key={section.title} className="space-y-4">
              <h3 className="px-2 text-sm font-medium uppercase tracking-wider text-zinc-400">{section.title}</h3>
              <div className="overflow-hidden rounded-3xl border border-white/5 bg-zinc-900">
                {section.items.map((item, index) => (
                  <div key={item.label} className={cn(index !== section.items.length - 1 && 'border-b border-white/5')}>
                    <SectionRow item={item} />
                  </div>
                ))}
              </div>
            </div>
          ))}

          <div className="flex flex-col items-center justify-center gap-4 pt-8 text-center">
            <Logo className="h-8 w-8 text-zinc-700" />
            <p className="text-[10px] uppercase tracking-[0.2em] text-zinc-600">
              Oxidity Advanced Configuration v1.1
            </p>
          </div>
        </div>
      </div>

      {showPasscodeSheet ? (
        <>
          <button
            onClick={() => setShowPasscodeSheet(false)}
            className="fixed inset-0 z-[60] bg-black/80 backdrop-blur-sm"
            aria-label="Close passcode sheet"
          />
          <div className="fixed inset-x-4 bottom-6 z-[61] rounded-[32px] border border-white/10 bg-zinc-950 p-6">
            <div className="mb-6">
              <h3 className="text-xl font-semibold">Change Passcode</h3>
              <p className="text-sm text-zinc-500">Rotate the 6-digit passcode used to unlock this wallet.</p>
            </div>

            <div className="space-y-4">
              <label className="block">
                <span className="mb-2 block text-xs font-bold uppercase tracking-widest text-zinc-500">Current Passcode</span>
                <input
                  inputMode="numeric"
                  maxLength={6}
                  type="password"
                  value={currentPasscode}
                  onChange={(event) => setCurrentPasscode(event.target.value.replace(/\D/g, '').slice(0, 6))}
                  className="w-full rounded-2xl border border-white/10 bg-zinc-900 px-4 py-3 text-white focus:border-indigo-500/50 focus:outline-none"
                />
              </label>
              <label className="block">
                <span className="mb-2 block text-xs font-bold uppercase tracking-widest text-zinc-500">New Passcode</span>
                <input
                  inputMode="numeric"
                  maxLength={6}
                  type="password"
                  value={nextPasscode}
                  onChange={(event) => setNextPasscode(event.target.value.replace(/\D/g, '').slice(0, 6))}
                  className="w-full rounded-2xl border border-white/10 bg-zinc-900 px-4 py-3 text-white focus:border-indigo-500/50 focus:outline-none"
                />
              </label>
              <label className="block">
                <span className="mb-2 block text-xs font-bold uppercase tracking-widest text-zinc-500">Confirm New Passcode</span>
                <input
                  inputMode="numeric"
                  maxLength={6}
                  type="password"
                  value={confirmPasscode}
                  onChange={(event) => setConfirmPasscode(event.target.value.replace(/\D/g, '').slice(0, 6))}
                  className="w-full rounded-2xl border border-white/10 bg-zinc-900 px-4 py-3 text-white focus:border-indigo-500/50 focus:outline-none"
                />
              </label>
            </div>

            <div className="mt-6 flex gap-3">
              <button
                onClick={() => setShowPasscodeSheet(false)}
                className="flex-1 rounded-2xl bg-zinc-900 py-3 font-medium text-white transition-colors hover:bg-zinc-800"
              >
                Cancel
              </button>
              <button
                onClick={() => void handleChangePasscode()}
                disabled={isChangingPasscode}
                className="flex-1 rounded-2xl bg-indigo-500 py-3 font-medium text-white transition-colors hover:bg-indigo-600 disabled:opacity-60"
              >
                {isChangingPasscode ? 'Updating…' : 'Update Passcode'}
              </button>
            </div>
          </div>
        </>
      ) : null}
    </motion.div>
  );
}
