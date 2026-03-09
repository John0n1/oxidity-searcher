import { lazy, Suspense, type ComponentType } from 'react';
import { Capacitor } from '@capacitor/core';
import { motion, AnimatePresence } from 'motion/react';
import { useAppStore } from '../store/appStore';
import { Home, Activity, ArrowLeftRight, BarChart3, Settings, LayoutGrid } from 'lucide-react';
import { cn } from '../utils/cn';

function lazyNamed<TModule extends Record<string, ComponentType<any>>, TKey extends keyof TModule>(
  loader: () => Promise<TModule>,
  name: TKey,
) {
  return lazy(async () => {
    const module = await loader();
    return { default: module[name] as ComponentType<any> };
  });
}

const HomeTab = lazyNamed(() => import('./main/HomeTab'), 'HomeTab');
const ActivityTab = lazyNamed(() => import('./main/ActivityTab'), 'ActivityTab');
const SwapTab = lazyNamed(() => import('./main/SwapTab'), 'SwapTab');
const NFTGalleryTab = lazyNamed(() => import('./main/NFTGalleryTab'), 'NFTGalleryTab');
const InsightsTab = lazyNamed(() => import('./main/InsightsTab'), 'InsightsTab');
const SettingsTab = lazyNamed(() => import('./main/SettingsTab'), 'SettingsTab');

const TABS = [
  { id: 'home', icon: Home, label: 'Home' },
  { id: 'activity', icon: Activity, label: 'Activity' },
  { id: 'swap', icon: ArrowLeftRight, label: 'Swap' },
  { id: 'nfts', icon: LayoutGrid, label: 'NFTs' },
  { id: 'insights', icon: BarChart3, label: 'Insights' },
  { id: 'settings', icon: Settings, label: 'Settings' },
] as const;

function TabFallback() {
  return (
    <div className="absolute inset-0 flex items-center justify-center bg-zinc-950">
      <div className="h-9 w-9 animate-spin rounded-full border-2 border-white/10 border-t-indigo-500" />
    </div>
  );
}

function MainTabView({ currentTab }: { currentTab: string }) {
  return (
    <>
      {currentTab === 'home' && <HomeTab key="home" />}
      {currentTab === 'activity' && <ActivityTab key="activity" />}
      {currentTab === 'swap' && <SwapTab key="swap" />}
      {currentTab === 'nfts' && <NFTGalleryTab key="nfts" />}
      {currentTab === 'insights' && <InsightsTab key="insights" />}
      {currentTab === 'settings' && <SettingsTab key="settings" />}
    </>
  );
}

export function MainView() {
  const currentTab = useAppStore((state) => state.currentTab);
  const setTab = useAppStore((state) => state.setTab);
  const isNativePlatform = Capacitor.isNativePlatform();

  return (
    <div className="absolute inset-0 flex flex-col overflow-hidden">
      <div className="relative flex-1 overflow-hidden overscroll-none">
        <Suspense fallback={<TabFallback />}>
          {isNativePlatform ? (
            <MainTabView currentTab={currentTab} />
          ) : (
            <AnimatePresence mode="wait">
              <MainTabView currentTab={currentTab} />
            </AnimatePresence>
          )}
        </Suspense>
      </div>

      <div className="h-20 bg-zinc-950/80 backdrop-blur-xl border-t border-white/5 flex items-center justify-around px-2 pb-safe">
        {TABS.map((tab) => {
          const Icon = tab.icon;
          const isActive = currentTab === tab.id;
          return (
            <button
              key={tab.id}
              onClick={() => setTab(tab.id as any)}
              className="flex flex-col items-center justify-center w-16 h-14 gap-1 relative"
            >
              {isActive && (
                isNativePlatform ? (
                  <div className="absolute -top-3 w-8 h-1 bg-indigo-500 rounded-b-full" />
                ) : (
                  <motion.div
                    layoutId="active-tab"
                    className="absolute -top-3 w-8 h-1 bg-indigo-500 rounded-b-full shadow-[0_0_10px_rgba(99,102,241,0.5)]"
                  />
                )
              )}
              <Icon
                className={cn(
                  'w-6 h-6 transition-colors duration-300',
                  isActive ? 'text-white' : 'text-zinc-500',
                )}
              />
              <span
                className={cn(
                  'text-[10px] font-medium transition-colors duration-300',
                  isActive ? 'text-white' : 'text-zinc-500',
                )}
              >
                {tab.label}
              </span>
            </button>
          );
        })}
      </div>
    </div>
  );
}
