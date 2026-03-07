import { useEffect } from 'react';
import { AnimatePresence } from 'motion/react';
import { useAppStore } from '@/store/appStore';
import { SplashView } from '@/views/SplashView';
import { WelcomeView } from '@/views/WelcomeView';
import { CreateWalletView } from '@/views/CreateWalletView';
import { ImportWalletView } from '@/views/ImportWalletView';
import { WalkthroughView } from '@/views/WalkthroughView';
import { MainView } from '@/views/MainView';
import { LockScreenView } from '@/views/LockScreenView';

export function WalletShell({ embedded = false }: { embedded?: boolean }) {
  const currentView = useAppStore((state) => state.currentView);
  const isLocked = useAppStore((state) => state.isLocked);
  const hydrate = useAppStore((state) => state.hydrate);
  const bootstrap = useAppStore((state) => state.bootstrap);

  useEffect(() => {
    void hydrate();
  }, [hydrate]);

  const frameClasses = embedded
    ? 'w-full h-[100dvh] overflow-hidden rounded-none border-0 bg-white/85 relative'
    : 'w-full h-[100dvh] sm:h-[844px] sm:w-[398px] overflow-hidden relative rounded-none border-0 bg-white/88 sm:rounded-[42px] sm:border border-white/70 shadow-[0_40px_100px_rgba(37,99,235,0.18)] no-scrollbar';

  return (
    <div className="relative min-h-screen overflow-hidden font-sans text-slate-950">
      <div className="pointer-events-none absolute inset-0">
        <div className="absolute -left-20 top-0 h-72 w-72 rounded-full bg-blue-400/18 blur-3xl" />
        <div className="absolute right-0 top-24 h-80 w-80 rounded-full bg-cyan-300/16 blur-3xl" />
        <div className="absolute bottom-0 left-1/3 h-72 w-72 rounded-full bg-emerald-300/12 blur-3xl" />
      </div>
      {!embedded ? (
        <div className="relative mx-auto flex min-h-screen max-w-6xl items-center justify-center gap-12 px-5 py-10 sm:px-8">
          <div className="hidden max-w-md flex-col gap-5 lg:flex">
            <div className="inline-flex w-fit items-center gap-2 rounded-full border border-blue-200 bg-white/80 px-3 py-1 text-xs font-semibold uppercase tracking-[0.18em] text-blue-700 backdrop-blur">
              Live wallet
            </div>
            <h1 className="text-5xl font-extrabold leading-[0.95] tracking-tight text-slate-950">
              {bootstrap?.productName ?? 'Oxidity Wallet'}
            </h1>
            <p className="text-lg leading-8 text-slate-600">
              {bootstrap?.tagline ??
                'A self-custody wallet built for cleaner Ethereum execution and a better path into production infrastructure.'}
            </p>
            <div className="grid gap-3 text-sm text-slate-600">
              <div className="rounded-3xl border border-white/70 bg-white/70 px-4 py-4 shadow-[0_18px_50px_rgba(15,23,42,0.06)]">
                Live multi-chain reads, private transaction handling, and business handoff now start from the same product surface.
              </div>
              <div className="rounded-3xl border border-white/70 bg-white/70 px-4 py-4 shadow-[0_18px_50px_rgba(15,23,42,0.06)]">
                The wallet keeps keys local. Backend services are only used for bootstrap, routing metadata, and future quoting APIs.
              </div>
            </div>
          </div>
          <div className={frameClasses}>
            <AnimatePresence mode="wait">
              {isLocked ? (
                <LockScreenView key="lock" />
              ) : (
                <>
                  {currentView === 'splash' && <SplashView key="splash" />}
                  {currentView === 'welcome' && <WelcomeView key="welcome" />}
                  {currentView === 'create-wallet' && <CreateWalletView key="create" />}
                  {currentView === 'import-wallet' && <ImportWalletView key="import" />}
                  {currentView === 'walkthrough' && <WalkthroughView key="walk" />}
                  {currentView === 'main' && <MainView key="main" />}
                </>
              )}
            </AnimatePresence>
          </div>
        </div>
      ) : (
        <div className="relative flex min-h-screen items-center justify-center">
          <div className={frameClasses}>
            <AnimatePresence mode="wait">
              {isLocked ? (
                <LockScreenView key="lock" />
              ) : (
                <>
                  {currentView === 'splash' && <SplashView key="splash" />}
                  {currentView === 'welcome' && <WelcomeView key="welcome" />}
                  {currentView === 'create-wallet' && <CreateWalletView key="create" />}
                  {currentView === 'import-wallet' && <ImportWalletView key="import" />}
                  {currentView === 'walkthrough' && <WalkthroughView key="walk" />}
                  {currentView === 'main' && <MainView key="main" />}
                </>
              )}
            </AnimatePresence>
          </div>
        </div>
      )}
    </div>
  );
}
