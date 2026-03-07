import { AnimatePresence, motion } from 'motion/react';
import { Activity, ArrowLeftRight, Home, Settings, Sparkles } from 'lucide-react';
import { useAppStore } from '../store/appStore';
import { cn } from '../utils/cn';
import { ActivityTab } from './main/ActivityTab';
import { HomeTab } from './main/HomeTab';
import { InsightsTab } from './main/InsightsTab';
import { SettingsTab } from './main/SettingsTab';
import { SwapTab } from './main/SwapTab';

const TABS = [
  { id: 'home', icon: Home, label: 'Home' },
  { id: 'activity', icon: Activity, label: 'Activity' },
  { id: 'swap', icon: ArrowLeftRight, label: 'Swap' },
  { id: 'insights', icon: Sparkles, label: 'Insights' },
  { id: 'settings', icon: Settings, label: 'Settings' },
] as const;

export function MainView() {
  const currentTab = useAppStore((state) => state.currentTab);
  const setTab = useAppStore((state) => state.setTab);

  return (
    <motion.div
      initial={{ opacity: 0, scale: 0.98 }}
      animate={{ opacity: 1, scale: 1 }}
      exit={{ opacity: 0, scale: 0.98 }}
      transition={{ duration: 0.35, ease: [0.22, 1, 0.36, 1] }}
      className="absolute inset-0 flex flex-col overflow-hidden bg-[linear-gradient(180deg,#f9fbff_0%,#eef6ff_54%,#f9fbff_100%)]"
    >
      <div className="flex-1 overflow-hidden">
        <AnimatePresence mode="wait">
          {currentTab === 'home' ? <HomeTab key="home" /> : null}
          {currentTab === 'activity' ? <ActivityTab key="activity" /> : null}
          {currentTab === 'swap' ? <SwapTab key="swap" /> : null}
          {currentTab === 'insights' ? <InsightsTab key="insights" /> : null}
          {currentTab === 'settings' ? <SettingsTab key="settings" /> : null}
        </AnimatePresence>
      </div>

      <div className="border-t border-white/80 bg-white/92 px-2 pb-[max(env(safe-area-inset-bottom),0.5rem)] pt-3 shadow-[0_-20px_50px_rgba(15,23,42,0.05)] backdrop-blur">
        <div className="flex items-center justify-around">
          {TABS.map((tab) => {
            const Icon = tab.icon;
            const isActive = currentTab === tab.id;
            return (
              <button
                key={tab.id}
                onClick={() => setTab(tab.id)}
                className="relative flex h-14 w-16 flex-col items-center justify-center gap-1"
              >
                {isActive ? (
                  <motion.div
                    layoutId="wallet-tab"
                    className="absolute inset-x-2 top-1 bottom-1 rounded-[1rem] bg-blue-50"
                  />
                ) : null}
                <Icon
                  className={cn(
                    'relative h-5 w-5 transition-colors',
                    isActive ? 'text-blue-700' : 'text-slate-400'
                  )}
                />
                <span
                  className={cn(
                    'relative text-[10px] font-semibold transition-colors',
                    isActive ? 'text-blue-700' : 'text-slate-500'
                  )}
                >
                  {tab.label}
                </span>
              </button>
            );
          })}
        </div>
      </div>
    </motion.div>
  );
}
