import { motion } from 'motion/react';
import { Activity, ArrowLeftRight, Copy, RefreshCw } from 'lucide-react';
import { useAppStore } from '../../store/appStore';

function shortenAddress(address: string): string {
  if (address.length < 12) {
    return address;
  }
  return `${address.slice(0, 6)}…${address.slice(-4)}`;
}

export function ActivityTab() {
  const activeAccountId = useAppStore((state) => state.activeAccountId);
  const accounts = useAppStore((state) => state.accounts);
  const portfolio = useAppStore((state) => state.portfolio);
  const portfolioRefreshing = useAppStore((state) => state.portfolioRefreshing);
  const refreshPortfolio = useAppStore((state) => state.refreshPortfolio);
  const activeAccount = accounts.find((account) => account.id === activeAccountId);

  return (
    <motion.div
      initial={{ opacity: 0, y: 10 }}
      animate={{ opacity: 1, y: 0 }}
      exit={{ opacity: 0, y: -10 }}
      transition={{ duration: 0.25 }}
      className="absolute inset-0 overflow-y-auto pb-28"
    >
      <div className="sticky top-0 z-10 border-b border-white/70 bg-white/88 px-6 pb-4 pt-6 backdrop-blur">
        <h2 className="text-2xl font-extrabold tracking-tight text-slate-950">Activity</h2>
        <p className="mt-2 text-sm leading-7 text-slate-600">
          Transaction history is still a separate indexing phase. Live chain reads are already online.
        </p>
      </div>

      <div className="px-6 py-6">
        <div className="rounded-[2rem] border border-white/80 bg-white/92 p-6 text-center shadow-[0_24px_70px_rgba(15,23,42,0.06)]">
          <div className="mx-auto flex h-16 w-16 items-center justify-center rounded-[1.5rem] bg-blue-50 text-blue-600">
            <Activity className="h-8 w-8" />
          </div>
          <h3 className="mt-6 text-2xl font-bold tracking-tight text-slate-950">No activity yet</h3>
          <p className="mt-3 text-[15px] leading-7 text-slate-600">
            This view does not invent transactions. Confirmed sends, receives, and swaps will appear here once the indexing layer is added.
          </p>

          <div className="mt-6 rounded-[1.5rem] border border-blue-200 bg-blue-50 px-4 py-3 text-left text-sm leading-7 text-blue-700">
            {portfolio
              ? `Live balances are currently being tracked across ${portfolio.summary.trackedChains} networks.`
              : 'Use refresh to confirm the current network state for this address.'}
          </div>

          {activeAccount ? (
            <div className="mt-6 rounded-[1.5rem] border border-slate-200 bg-slate-50 p-4 text-left">
              <div className="text-xs font-semibold uppercase tracking-[0.18em] text-slate-500">Watching account</div>
              <div className="mt-3 text-lg font-bold text-slate-950">{activeAccount.name}</div>
              <div className="mt-2 font-mono text-sm text-slate-600">{activeAccount.address}</div>
            </div>
          ) : null}

          <div className="mt-6 grid gap-3 sm:grid-cols-2">
            <button
              onClick={() => {
                if (activeAccount?.address) {
                  void navigator.clipboard.writeText(activeAccount.address);
                }
              }}
              className="flex items-center justify-center gap-2 rounded-[1.2rem] border border-slate-200 bg-slate-50 px-4 py-3 font-semibold text-slate-700 transition-colors hover:border-slate-300 hover:bg-white"
            >
              <Copy className="h-4 w-4" />
              Copy receive address
            </button>
            <button
              onClick={() => {
                void refreshPortfolio(activeAccount?.address);
              }}
              className="flex items-center justify-center gap-2 rounded-[1.2rem] border border-slate-200 bg-slate-50 px-4 py-3 font-semibold text-slate-700 transition-colors hover:border-slate-300 hover:bg-white"
            >
              <RefreshCw className={`h-4 w-4 ${portfolioRefreshing ? 'animate-spin' : ''}`} />
              Refresh live balances
            </button>
          </div>

          <div className="mt-6 rounded-[1.5rem] border border-slate-200 bg-slate-50 px-4 py-3 text-sm leading-7 text-slate-600">
            Next engine step: signed send flow, receipt tracking, and opt-in activity indexing.
          </div>
        </div>
      </div>
    </motion.div>
  );
}
