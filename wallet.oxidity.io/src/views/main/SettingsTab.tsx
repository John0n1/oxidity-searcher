import { motion } from 'motion/react';
import {
  Bell,
  ChevronRight,
  Copy,
  FileText,
  Fingerprint,
  HelpCircle,
  KeyRound,
  LogOut,
  Moon,
  Shield,
  Smartphone,
  Wallet,
} from 'lucide-react';
import { useAppStore } from '../../store/appStore';
import { cn } from '../../utils/cn';

export function SettingsTab() {
  const biometricsEnabled = useAppStore((state) => state.biometricsEnabled);
  const setBiometricsEnabled = useAppStore((state) => state.setBiometricsEnabled);
  const activeAccountId = useAppStore((state) => state.activeAccountId);
  const accounts = useAppStore((state) => state.accounts);
  const activeAccount = accounts.find((account) => account.id === activeAccountId);

  const sections = [
    {
      title: 'Wallet',
      items: [
        { icon: Wallet, label: 'Managed wallets', value: `${accounts.length}` },
        { icon: Smartphone, label: 'Target platforms', value: 'Web, extension, Android' },
      ],
    },
    {
      title: 'Security',
      items: [
        { icon: KeyRound, label: 'Recovery handling', value: 'Local only', warning: false },
        { icon: Shield, label: 'Vault encryption', value: 'PBKDF2 + AES-GCM', warning: false },
        {
          icon: Fingerprint,
          label: 'Biometrics',
          value: biometricsEnabled ? 'Enabled' : 'Disabled',
          onClick: () => {
            void setBiometricsEnabled(!biometricsEnabled);
          },
        },
      ],
    },
    {
      title: 'Preferences',
      items: [
        { icon: Bell, label: 'Notifications', value: 'Later phase' },
        { icon: Moon, label: 'Theme', value: 'Light default' },
      ],
    },
    {
      title: 'About',
      items: [
        { icon: HelpCircle, label: 'Support', value: 'support@oxidity.io' },
        { icon: FileText, label: 'Legal and privacy', value: 'On oxidity.io' },
      ],
    },
  ];

  return (
    <motion.div
      initial={{ opacity: 0, y: 10 }}
      animate={{ opacity: 1, y: 0 }}
      exit={{ opacity: 0, y: -10 }}
      transition={{ duration: 0.25 }}
      className="absolute inset-0 overflow-y-auto pb-28"
    >
      <div className="sticky top-0 z-10 border-b border-white/70 bg-white/88 px-6 pb-4 pt-6 backdrop-blur">
        <h2 className="text-2xl font-extrabold tracking-tight text-slate-950">Settings</h2>
      </div>

      <div className="space-y-6 px-6 py-6">
        <div className="rounded-[2rem] border border-white/80 bg-white/92 p-5 shadow-[0_24px_70px_rgba(15,23,42,0.06)]">
          <div className="flex items-center gap-4">
            <div className="flex h-14 w-14 items-center justify-center rounded-full bg-blue-50">
              <img src="/brand-mark.svg" alt="" className="h-7 w-7" />
            </div>
            <div className="min-w-0 flex-1">
              <div className="text-lg font-bold tracking-tight text-slate-950">{activeAccount?.name ?? 'Main wallet'}</div>
              <div className="mt-1 truncate font-mono text-sm text-slate-500">{activeAccount?.address ?? 'No active account'}</div>
            </div>
            {activeAccount?.address ? (
              <button
                onClick={() => {
                  void navigator.clipboard.writeText(activeAccount.address);
                }}
                className="flex items-center gap-2 rounded-full border border-slate-200 bg-slate-50 px-4 py-2 text-sm font-semibold text-slate-700 transition-colors hover:border-slate-300 hover:bg-white"
              >
                <Copy className="h-4 w-4" />
                Copy
              </button>
            ) : null}
          </div>
        </div>

        {sections.map((section) => (
          <div key={section.title}>
            <h3 className="px-2 text-xs font-semibold uppercase tracking-[0.18em] text-slate-500">{section.title}</h3>
            <div className="mt-3 overflow-hidden rounded-[1.8rem] border border-slate-200 bg-white">
              {section.items.map((item, index) => (
                <button
                  key={item.label}
                  onClick={item.onClick}
                  className={cn(
                    'flex w-full items-center justify-between px-4 py-4 text-left transition-colors hover:bg-slate-50',
                    index !== section.items.length - 1 ? 'border-b border-slate-100' : ''
                  )}
                >
                  <div className="flex items-center gap-3">
                    <div className="flex h-10 w-10 items-center justify-center rounded-[1rem] bg-slate-50 text-slate-500">
                      <item.icon className="h-4 w-4" />
                    </div>
                    <div>
                      <div className="font-semibold text-slate-950">{item.label}</div>
                      <div className="text-sm text-slate-500">{item.value}</div>
                    </div>
                  </div>
                  <ChevronRight className="h-4 w-4 text-slate-400" />
                </button>
              ))}
            </div>
          </div>
        ))}

        <button
          onClick={() => {
            useAppStore.getState().setIsLocked(true);
          }}
          className="flex w-full items-center justify-center gap-2 rounded-[1.3rem] border border-rose-200 bg-rose-50 px-5 py-4 font-semibold text-rose-600 transition-colors hover:bg-rose-100"
        >
          <LogOut className="h-4 w-4" />
          Lock wallet
        </button>
      </div>
    </motion.div>
  );
}
