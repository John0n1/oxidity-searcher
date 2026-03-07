import { motion } from 'motion/react';
import { ArrowRight, BriefcaseBusiness, PlayCircle, WalletCards } from 'lucide-react';
import { useAppStore } from '../store/appStore';

export function WelcomeView() {
  const setView = useAppStore((state) => state.setView);
  const startCreateFlow = useAppStore((state) => state.startCreateFlow);
  const setImportMethod = useAppStore((state) => state.setImportMethod);
  const bootstrap = useAppStore((state) => state.bootstrap);

  return (
    <motion.div
      initial={{ opacity: 0, scale: 0.97 }}
      animate={{ opacity: 1, scale: 1 }}
      exit={{ opacity: 0, x: -18 }}
      transition={{ duration: 0.35, ease: [0.22, 1, 0.36, 1] }}
      className="absolute inset-0 overflow-y-auto bg-transparent px-6 pb-8 pt-8"
    >
      <div className="rounded-[2rem] border border-white/80 bg-white/88 p-6 shadow-[0_30px_80px_rgba(15,23,42,0.08)] backdrop-blur">
        <div className="inline-flex items-center gap-2 rounded-full border border-blue-200 bg-blue-50 px-3 py-1 text-[11px] font-semibold uppercase tracking-[0.18em] text-blue-700">
          Self-custody with private execution
        </div>
        <div className="mt-6 flex items-start justify-between gap-4">
          <div>
            <h1 className="max-w-[280px] text-[2.2rem] font-extrabold leading-[0.98] tracking-tight text-slate-950">
              {bootstrap?.copy.welcomeTitle ?? 'Ethereum, without the rough edges'}
            </h1>
            <p className="mt-4 text-[15px] leading-7 text-slate-600">
              {bootstrap?.copy.welcomeBody ??
                'Create or import a wallet, keep your keys local, and use Oxidity when you want cleaner transaction handling than a generic public RPC gives you.'}
            </p>
          </div>
          <div className="flex h-14 w-14 shrink-0 items-center justify-center rounded-[1.4rem] bg-[linear-gradient(135deg,#dbeafe_0%,#ffffff_50%,#dcfce7_100%)] shadow-inner">
            <img src="/brand-mark.svg" alt="" className="h-8 w-8" />
          </div>
        </div>

        <div className="mt-8 grid gap-3">
          <button
            onClick={() => startCreateFlow()}
            className="flex items-center justify-between rounded-[1.4rem] bg-slate-950 px-5 py-4 text-left text-white shadow-[0_16px_32px_rgba(15,23,42,0.18)] transition-transform hover:-translate-y-0.5 hover:bg-slate-900"
          >
            <div>
              <div className="font-semibold">Create a new wallet</div>
              <div className="mt-1 text-sm text-slate-300">Generate a recovery phrase and encrypt it locally on this device.</div>
            </div>
            <ArrowRight className="h-5 w-5" />
          </button>

          <button
            onClick={() => {
              setImportMethod('mnemonic');
              setView('import-wallet');
            }}
            className="flex items-center justify-between rounded-[1.4rem] border border-slate-200 bg-slate-50 px-5 py-4 text-left text-slate-950 transition-colors hover:border-slate-300 hover:bg-white"
          >
            <div>
              <div className="font-semibold">Import an existing wallet</div>
              <div className="mt-1 text-sm text-slate-600">Use a recovery phrase or private key you already control.</div>
            </div>
            <WalletCards className="h-5 w-5 text-slate-500" />
          </button>
        </div>

        <div className="mt-8 grid gap-3 sm:grid-cols-2">
          <button
            onClick={() => setView('walkthrough')}
            className="flex items-center justify-center gap-2 rounded-[1.2rem] border border-slate-200 bg-white px-4 py-3 text-sm font-semibold text-slate-700 transition-colors hover:border-slate-300 hover:text-slate-950"
          >
            <PlayCircle className="h-4 w-4" />
            Quick walkthrough
          </button>
          <a
            href="https://oxidity.io/partners?requested=wallet"
            className="flex items-center justify-center gap-2 rounded-[1.2rem] border border-blue-200 bg-blue-50 px-4 py-3 text-sm font-semibold text-blue-700 transition-colors hover:bg-blue-100"
          >
            <BriefcaseBusiness className="h-4 w-4" />
            Business onboarding
          </a>
        </div>
      </div>
    </motion.div>
  );
}
