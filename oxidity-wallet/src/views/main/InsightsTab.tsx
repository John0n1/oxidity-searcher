import { Capacitor } from '@capacitor/core';
import { motion } from 'motion/react';
import { BarChart3, ShieldCheck, Zap, Coins, TrendingUp, Calendar } from 'lucide-react';
import { useAppStore } from '../../store/appStore';

function formatUsd(value: number): string {
  return value.toLocaleString('en-US', {
    minimumFractionDigits: 2,
    maximumFractionDigits: 2,
  });
}

export function InsightsTab() {
  const insights = useAppStore((state) => state.insights);
  const refreshWalletData = useAppStore((state) => state.refreshWalletData);
  const isNativePlatform = Capacitor.isNativePlatform();
  const ScreenWrapper: any = isNativePlatform ? 'div' : motion.div;

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
      className="absolute inset-0 overflow-y-auto pb-24"
    >
      {/* Header */}
      <div className="flex items-center justify-between p-6 pb-4 sticky top-0 bg-zinc-950/80 backdrop-blur-xl z-10 border-b border-white/5">
        <h2 className="text-2xl font-semibold tracking-tight">Insights</h2>
        <button
          onClick={() => void refreshWalletData()}
          className="flex items-center gap-2 bg-zinc-900 border border-white/5 px-3 py-1.5 rounded-full hover:bg-zinc-800 transition-colors text-sm font-medium text-zinc-400"
        >
          <Calendar className="w-4 h-4" />
          Refresh
        </button>
      </div>

      <div className="px-6 py-4 space-y-6">
        {/* Main Stat */}
        <div className="bg-gradient-to-br from-indigo-500/20 to-purple-500/5 border border-indigo-500/20 rounded-3xl p-6 relative overflow-hidden">
          {!isNativePlatform ? (
            <div className="absolute top-0 right-0 w-32 h-32 bg-indigo-500/20 blur-3xl rounded-full" />
          ) : null}
          <div className="relative z-10">
            <div className="flex items-center gap-2 text-indigo-300 font-medium mb-2">
              <TrendingUp className="w-5 h-5" />
              Total Value Saved
            </div>
            <div className="text-5xl font-semibold tracking-tight text-white mb-4">
              ${formatUsd(insights.totalSavedUsd)}
            </div>
            <p className="text-indigo-200/60 text-sm max-w-[200px] leading-relaxed">
              Through private routing, MEV protection, and gas rebates.
            </p>
          </div>
        </div>

        {/* Grid Stats */}
        <div className="grid grid-cols-2 gap-4">
          <div className="bg-zinc-900 border border-white/5 rounded-3xl p-5 flex flex-col gap-3">
            <div className="w-10 h-10 bg-amber-500/10 rounded-2xl flex items-center justify-center">
              <Coins className="w-5 h-5 text-amber-400" />
            </div>
            <div>
              <div className="text-2xl font-semibold text-white mb-1">${formatUsd(insights.rebatesUsd)}</div>
              <div className="text-sm font-medium text-zinc-500">Rebates Earned</div>
            </div>
          </div>

          <div className="bg-zinc-900 border border-white/5 rounded-3xl p-5 flex flex-col gap-3">
            <div className="w-10 h-10 bg-indigo-500/10 rounded-2xl flex items-center justify-center">
              <Zap className="w-5 h-5 text-indigo-400" />
            </div>
            <div>
              <div className="text-2xl font-semibold text-white mb-1">${formatUsd(insights.gasSavedUsd)}</div>
              <div className="text-sm font-medium text-zinc-500">Gas Saved</div>
            </div>
          </div>

          <div className="bg-zinc-900 border border-white/5 rounded-3xl p-5 flex flex-col gap-3">
            <div className="w-10 h-10 bg-emerald-500/10 rounded-2xl flex items-center justify-center">
              <ShieldCheck className="w-5 h-5 text-emerald-400" />
            </div>
            <div>
              <div className="text-2xl font-semibold text-white mb-1">{insights.protectedTxCount}</div>
              <div className="text-sm font-medium text-zinc-500">Protected Txs</div>
            </div>
          </div>

          <div className="bg-zinc-900 border border-white/5 rounded-3xl p-5 flex flex-col gap-3">
            <div className="w-10 h-10 bg-blue-500/10 rounded-2xl flex items-center justify-center">
              <BarChart3 className="w-5 h-5 text-blue-400" />
            </div>
            <div>
              <div className="text-2xl font-semibold text-white mb-1">{insights.privateRoutingPct.toFixed(0)}%</div>
              <div className="text-sm font-medium text-zinc-500">Private Routing</div>
            </div>
          </div>
        </div>

        {/* Empty State Chart Area */}
        <div className="bg-zinc-900 border border-white/5 rounded-3xl p-6 flex flex-col items-center justify-center text-center h-48">
          <BarChart3 className="w-8 h-8 text-zinc-600 mb-3" />
          <h4 className="font-semibold text-zinc-300 mb-1">Performance History</h4>
          <p className="text-sm text-zinc-500 max-w-[200px]">
            Charts will appear here once you start transacting.
          </p>
        </div>
      </div>
    </ScreenWrapper>
  );
}
