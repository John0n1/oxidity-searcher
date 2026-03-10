import { lazy, Suspense, useEffect, type ComponentType } from 'react';
import { Capacitor } from '@capacitor/core';
import { App as CapacitorApp } from '@capacitor/app';
import { AnimatePresence, MotionConfig } from 'motion/react';

import { BackgroundAnimation } from './components/BackgroundAnimation';
import { getBackgroundPreloadTokens } from './lib/walletDefaults';
import { applyThemeMode, readThemeMode } from './lib/theme';
import { preloadTokenLogos } from './lib/tokenLogos';
import { useAppStore } from './store/appStore';

const AUTO_LOCK_IDLE_MS = 5 * 60 * 1000;

function lazyNamed<TModule extends Record<string, ComponentType<any>>, TKey extends keyof TModule>(
  loader: () => Promise<TModule>,
  name: TKey,
) {
  return lazy(async () => {
    const module = await loader();
    return { default: module[name] as ComponentType<any> };
  });
}

const SplashView = lazyNamed(() => import('./views/SplashView'), 'SplashView');
const WelcomeView = lazyNamed(() => import('./views/WelcomeView'), 'WelcomeView');
const CreateWalletView = lazyNamed(() => import('./views/CreateWalletView'), 'CreateWalletView');
const ImportWalletView = lazyNamed(() => import('./views/ImportWalletView'), 'ImportWalletView');
const WalkthroughView = lazyNamed(() => import('./views/WalkthroughView'), 'WalkthroughView');
const MainView = lazyNamed(() => import('./views/MainView'), 'MainView');
const LockScreenView = lazyNamed(() => import('./views/LockScreenView'), 'LockScreenView');
const TokenManagementView = lazyNamed(
  () => import('./views/TokenManagementView'),
  'TokenManagementView',
);
const TokenDetailsView = lazyNamed(
  () => import('./views/TokenDetailsView'),
  'TokenDetailsView',
);
const SendView = lazyNamed(() => import('./views/SendView'), 'SendView');
const BuyView = lazyNamed(() => import('./views/BuyView'), 'BuyView');
const LegalView = lazyNamed(() => import('./views/LegalView'), 'LegalView');
const SupportView = lazyNamed(() => import('./views/SupportView'), 'SupportView');
const AdvancedSettingsView = lazyNamed(
  () => import('./views/AdvancedSettingsView'),
  'AdvancedSettingsView',
);
const LicensesView = lazyNamed(() => import('./views/LicensesView'), 'LicensesView');
const AIView = lazyNamed(() => import('./views/AIView'), 'AIView');
const SubscriptionView = lazyNamed(() => import('./views/SubscriptionView'), 'SubscriptionView');
const TransactionDetailsView = lazyNamed(
  () => import('./views/TransactionDetailsView'),
  'TransactionDetailsView',
);
const ReceiveView = lazyNamed(() => import('./views/ReceiveView'), 'ReceiveView');
const ReceiveQRView = lazyNamed(() => import('./views/ReceiveQRView'), 'ReceiveQRView');
const AddressBookView = lazyNamed(() => import('./views/AddressBookView'), 'AddressBookView');

function ViewFallback() {
  return (
    <div className="absolute inset-0 flex items-center justify-center bg-zinc-950">
      <div className="h-10 w-10 animate-spin rounded-full border-2 border-white/10 border-t-indigo-500" />
    </div>
  );
}

function AppView({ currentView }: { currentView: string }) {
  return (
    <>
      {currentView === 'splash' && <SplashView key="splash" />}
      {currentView === 'welcome' && <WelcomeView key="welcome" />}
      {currentView === 'create-wallet' && <CreateWalletView key="create" />}
      {currentView === 'import-wallet' && <ImportWalletView key="import" />}
      {currentView === 'walkthrough' && <WalkthroughView key="walk" />}
      {currentView === 'token-management' && <TokenManagementView key="token-management" />}
      {currentView === 'token-details' && <TokenDetailsView key="token-details" />}
      {currentView === 'send' && <SendView key="send" />}
      {currentView === 'buy' && <BuyView key="buy" />}
      {currentView === 'legal' && <LegalView key="legal" />}
      {currentView === 'support' && <SupportView key="support" />}
      {currentView === 'advanced' && <AdvancedSettingsView key="advanced" />}
      {currentView === 'licenses' && <LicensesView key="licenses" />}
      {currentView === 'ai' && <AIView key="ai" />}
      {currentView === 'subscription' && <SubscriptionView key="subscription" />}
      {currentView === 'transaction-details' && <TransactionDetailsView key="transaction-details" />}
      {currentView === 'receive' && <ReceiveView key="receive" />}
      {currentView === 'receive-qr' && <ReceiveQRView key="receive-qr" />}
      {currentView === 'address-book' && <AddressBookView key="address-book" />}
      {currentView === 'main' && <MainView key="main" />}
    </>
  );
}

export default function App() {
  const initialize = useAppStore((state) => state.initialize);
  const currentView = useAppStore((state) => state.currentView);
  const isLocked = useAppStore((state) => state.isLocked);
  const walletCreated = useAppStore((state) => state.walletCreated);
  const setIsLocked = useAppStore((state) => state.setIsLocked);
  const customTokens = useAppStore((state) => state.customTokens);
  const activeChainKey = useAppStore((state) => state.activeChainKey);

  useEffect(() => {
    applyThemeMode(readThemeMode());
    void initialize();
  }, [initialize]);

  const isNativePlatform = Capacitor.isNativePlatform();

  useEffect(() => {
    document.documentElement.dataset.platform = isNativePlatform ? 'native' : 'web';
  }, [isNativePlatform]);

  useEffect(() => {
    void preloadTokenLogos(getBackgroundPreloadTokens(activeChainKey, customTokens));
  }, [activeChainKey, customTokens]);

  useEffect(() => {
    if (!walletCreated) {
      return;
    }

    const handleVisibilityChange = () => {
      if (document.hidden) {
        setIsLocked(true);
      }
    };

    document.addEventListener('visibilitychange', handleVisibilityChange);
    return () => {
      document.removeEventListener('visibilitychange', handleVisibilityChange);
    };
  }, [setIsLocked, walletCreated]);

  useEffect(() => {
    if (!walletCreated || isLocked) {
      return;
    }

    let timer = window.setTimeout(() => {
      setIsLocked(true);
    }, AUTO_LOCK_IDLE_MS);

    const resetTimer = () => {
      window.clearTimeout(timer);
      timer = window.setTimeout(() => {
        setIsLocked(true);
      }, AUTO_LOCK_IDLE_MS);
    };

    const events: Array<keyof WindowEventMap> = ['pointerdown', 'keydown', 'scroll', 'focus'];
    events.forEach((eventName) => {
      window.addEventListener(eventName, resetTimer);
    });

    return () => {
      window.clearTimeout(timer);
      events.forEach((eventName) => {
        window.removeEventListener(eventName, resetTimer);
      });
    };
  }, [isLocked, setIsLocked, walletCreated]);

  useEffect(() => {
    if (!isNativePlatform || !walletCreated) {
      return;
    }

    let listener: { remove: () => Promise<void> } | null = null;
    void CapacitorApp.addListener('appStateChange', ({ isActive }) => {
      if (!isActive) {
        setIsLocked(true);
      }
    }).then((handle) => {
      listener = handle;
    });

    return () => {
      void listener?.remove();
    };
  }, [isNativePlatform, setIsLocked, walletCreated]);

  const showBackground =
    ['welcome', 'create-wallet', 'import-wallet', 'splash', 'walkthrough'].includes(currentView)
    || (!isNativePlatform && currentView === 'main');

  return (
    <MotionConfig reducedMotion={isNativePlatform ? 'always' : 'never'}>
      <div className="min-h-screen bg-black text-white flex items-center justify-center sm:p-4 font-sans selection:bg-indigo-500/30">
        <div className="w-full h-[100dvh] sm:h-[844px] sm:w-[390px] bg-zinc-950 sm:rounded-[40px] sm:border-[8px] border-zinc-900 overflow-hidden relative shadow-2xl shadow-indigo-500/10 no-scrollbar overscroll-none">
          {showBackground && <BackgroundAnimation />}
          <Suspense fallback={<ViewFallback />}>
            {isNativePlatform ? (
              isLocked ? <LockScreenView key="lock" /> : <AppView currentView={currentView} />
            ) : (
              <AnimatePresence mode="wait">
                {isLocked ? <LockScreenView key="lock" /> : <AppView currentView={currentView} />}
              </AnimatePresence>
            )}
          </Suspense>
        </div>
      </div>
    </MotionConfig>
  );
}
