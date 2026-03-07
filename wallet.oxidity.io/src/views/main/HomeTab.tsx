import { useState } from 'react';
import { AnimatePresence, motion } from 'motion/react';
import {
  ArrowDownToLine,
  ArrowLeftRight,
  Check,
  ChevronDown,
  Copy,
  Edit2,
  ExternalLink,
  LoaderCircle,
  Plus,
  RefreshCw,
  Send,
  ShieldCheck,
  WalletMinimal,
  X,
} from 'lucide-react';
import { useAppStore } from '../../store/appStore';
import { cn } from '../../utils/cn';

function shortenAddress(address: string): string {
  if (address.length < 12) {
    return address;
  }
  return `${address.slice(0, 6)}…${address.slice(-4)}`;
}

export function HomeTab() {
  const balance = useAppStore((state) => state.balance);
  const accounts = useAppStore((state) => state.accounts);
  const activeAccountId = useAppStore((state) => state.activeAccountId);
  const setActiveAccount = useAppStore((state) => state.setActiveAccount);
  const addAccount = useAppStore((state) => state.addAccount);
  const renameAccount = useAppStore((state) => state.renameAccount);
  const setTab = useAppStore((state) => state.setTab);
  const refreshPortfolio = useAppStore((state) => state.refreshPortfolio);
  const portfolio = useAppStore((state) => state.portfolio);
  const portfolioError = useAppStore((state) => state.portfolioError);
  const portfolioRefreshing = useAppStore((state) => state.portfolioRefreshing);
  const bootstrap = useAppStore((state) => state.bootstrap);
  const canAddAccount = useAppStore((state) => state.vaultData?.source === 'mnemonic');

  const activeAccount = accounts.find((account) => account.id === activeAccountId);
  const primaryChain =
    portfolio?.chains.find((chain) => chain.chainId === bootstrap?.defaultChainId) ?? portfolio?.chains[0];
  const trackedChains = portfolio?.summary.trackedChains ?? bootstrap?.chains.length ?? 0;
  const healthyChains = portfolio?.summary.healthyChains ?? 0;
  const fundedChains = portfolio?.summary.fundedChains ?? 0;

  const [isSwitcherOpen, setIsSwitcherOpen] = useState(false);
  const [editingId, setEditingId] = useState<string | null>(null);
  const [editName, setEditName] = useState('');
  const [copyFeedback, setCopyFeedback] = useState('');

  const handleCopy = async (value: string) => {
    try {
      await navigator.clipboard.writeText(value);
      setCopyFeedback('Address copied');
      window.setTimeout(() => setCopyFeedback(''), 1400);
    } catch {
      setCopyFeedback('Copy failed');
      window.setTimeout(() => setCopyFeedback(''), 1400);
    }
  };

  const saveEdit = () => {
    if (editingId && editName.trim()) {
      void renameAccount(editingId, editName.trim());
    }
    setEditingId(null);
  };

  return (
    <motion.div
      initial={{ opacity: 0, y: 10 }}
      animate={{ opacity: 1, y: 0 }}
      exit={{ opacity: 0, y: -10 }}
      transition={{ duration: 0.25 }}
      className="absolute inset-0 overflow-y-auto pb-28"
    >
      <div className="sticky top-0 z-10 border-b border-white/70 bg-white/88 px-6 pb-4 pt-6 backdrop-blur">
        <div className="flex items-center justify-between">
          <button
            onClick={() => setIsSwitcherOpen(true)}
            className="flex items-center gap-3 rounded-full border border-slate-200 bg-white px-4 py-2.5 shadow-sm transition-colors hover:border-slate-300"
          >
            <div className="flex h-9 w-9 items-center justify-center rounded-full bg-blue-50">
              <img src="/brand-mark.svg" alt="" className="h-5 w-5" />
            </div>
            <div className="text-left">
              <div className="text-sm font-semibold text-slate-950">{activeAccount?.name ?? 'Main wallet'}</div>
              <div className="text-xs font-medium text-slate-500">{shortenAddress(activeAccount?.address ?? '')}</div>
            </div>
            <ChevronDown className="h-4 w-4 text-slate-400" />
          </button>
          {copyFeedback ? <div className="text-xs font-semibold text-blue-700">{copyFeedback}</div> : null}
        </div>
      </div>

      <AnimatePresence>
        {isSwitcherOpen ? (
          <>
            <motion.div
              initial={{ opacity: 0 }}
              animate={{ opacity: 1 }}
              exit={{ opacity: 0 }}
              onClick={() => setIsSwitcherOpen(false)}
              className="fixed inset-0 z-20 bg-slate-950/20 backdrop-blur-sm"
            />
            <motion.div
              initial={{ opacity: 0, y: 80 }}
              animate={{ opacity: 1, y: 0 }}
              exit={{ opacity: 0, y: 80 }}
              className="fixed bottom-0 left-0 right-0 z-30 rounded-t-[2.2rem] border border-slate-200 bg-white p-6 shadow-[0_-20px_70px_rgba(15,23,42,0.18)]"
            >
              <div className="mb-5 flex items-center justify-between">
                <h3 className="text-xl font-bold tracking-tight text-slate-950">Wallets</h3>
                <button
                  onClick={() => setIsSwitcherOpen(false)}
                  className="flex h-10 w-10 items-center justify-center rounded-full border border-slate-200 bg-slate-50 text-slate-500 transition-colors hover:text-slate-950"
                >
                  <X className="h-4 w-4" />
                </button>
              </div>
              <div className="space-y-3">
                {accounts.map((account) => (
                  <button
                    key={account.id}
                    onClick={() => {
                      if (editingId !== account.id) {
                        void setActiveAccount(account.id);
                        setIsSwitcherOpen(false);
                      }
                    }}
                    className={cn(
                      'flex w-full items-center justify-between rounded-[1.4rem] border p-4 text-left transition-colors',
                      activeAccountId === account.id
                        ? 'border-blue-200 bg-blue-50'
                        : 'border-slate-200 bg-slate-50 hover:border-slate-300 hover:bg-white'
                    )}
                  >
                    <div className="flex items-center gap-3">
                      <div className="flex h-10 w-10 items-center justify-center rounded-full bg-white shadow-sm">
                        <WalletMinimal className="h-5 w-5 text-blue-700" />
                      </div>
                      <div>
                        {editingId === account.id ? (
                          <input
                            autoFocus
                            value={editName}
                            onClick={(event) => event.stopPropagation()}
                            onChange={(event) => setEditName(event.target.value)}
                            onBlur={saveEdit}
                            onKeyDown={(event) => {
                              if (event.key === 'Enter') {
                                saveEdit();
                              }
                            }}
                            className="rounded-lg border border-blue-200 bg-white px-2 py-1 text-sm font-semibold text-slate-950 focus:outline-none"
                          />
                        ) : (
                          <div className="flex items-center gap-2 text-sm font-semibold text-slate-950">
                            {account.name}
                            <span
                              onClick={(event) => {
                                event.stopPropagation();
                                setEditingId(account.id);
                                setEditName(account.name);
                              }}
                              className="cursor-pointer text-slate-400 transition-colors hover:text-slate-700"
                            >
                              <Edit2 className="h-3.5 w-3.5" />
                            </span>
                          </div>
                        )}
                        <div className="mt-1 text-xs font-medium text-slate-500">{shortenAddress(account.address)}</div>
                      </div>
                    </div>
                    {activeAccountId === account.id ? <Check className="h-5 w-5 text-blue-700" /> : null}
                  </button>
                ))}
              </div>
              <button
                onClick={() => {
                  void addAccount(`Wallet ${accounts.length + 1}`);
                }}
                disabled={!canAddAccount}
                className="mt-4 flex w-full items-center justify-center gap-2 rounded-[1.25rem] border border-slate-200 bg-slate-50 px-4 py-4 font-semibold text-slate-700 transition-colors hover:border-slate-300 hover:bg-white disabled:cursor-not-allowed disabled:opacity-60"
              >
                <Plus className="h-4 w-4" />
                {canAddAccount ? 'Add derived wallet' : 'Mnemonic vault required'}
              </button>
            </motion.div>
          </>
        ) : null}
      </AnimatePresence>

      <div className="px-6 py-6">
        <div className="rounded-[2rem] border border-white/80 bg-white/92 p-6 shadow-[0_24px_70px_rgba(15,23,42,0.06)]">
          <div className="flex items-start justify-between gap-4">
            <div>
              <div className="text-xs font-semibold uppercase tracking-[0.18em] text-slate-500">
                Primary network
              </div>
              <div className="mt-4 text-4xl font-extrabold tracking-tight text-slate-950">
                {primaryChain?.balanceDisplay && primaryChain?.nativeCurrency
                  ? `${primaryChain.balanceDisplay} ${primaryChain.nativeCurrency}`
                  : `${balance.toFixed(6)} ${portfolio?.summary.defaultChainSymbol ?? 'ETH'}`}
              </div>
              <div className="mt-2 text-sm font-medium text-slate-500">
                {primaryChain
                  ? `${primaryChain.name} via ${primaryChain.sourceLabel === 'local-node' ? 'local node' : 'PublicNode'}`
                  : 'Connect the wallet to load live chain balances.'}
              </div>
            </div>
            <button
              onClick={() => {
                void refreshPortfolio(activeAccount?.address);
              }}
              className="inline-flex items-center gap-2 rounded-full border border-slate-200 bg-white px-4 py-2 text-sm font-semibold text-slate-700 transition-colors hover:border-slate-300"
            >
              {portfolioRefreshing ? <LoaderCircle className="h-4 w-4 animate-spin" /> : <RefreshCw className="h-4 w-4" />}
              {portfolioRefreshing ? 'Refreshing' : 'Refresh'}
            </button>
          </div>

          <div className="mt-5 grid grid-cols-3 gap-3">
            {[
              { label: 'Tracked', value: trackedChains },
              { label: 'Healthy', value: healthyChains },
              { label: 'Funded', value: fundedChains },
            ].map((item) => (
              <div key={item.label} className="rounded-[1.2rem] border border-slate-200 bg-slate-50 px-4 py-3">
                <div className="text-[11px] font-semibold uppercase tracking-[0.18em] text-slate-500">{item.label}</div>
                <div className="mt-2 text-xl font-bold text-slate-950">{item.value}</div>
              </div>
            ))}
          </div>

          {portfolioError ? (
            <div className="mt-5 rounded-[1.4rem] border border-amber-200 bg-amber-50 px-4 py-3 text-sm font-medium text-amber-700">
              Live balance refresh failed. {portfolioError}
            </div>
          ) : null}

          <div className="mt-6 grid grid-cols-4 gap-3">
            {[
              { icon: Send, label: 'Send', onClick: () => undefined },
              { icon: ArrowDownToLine, label: 'Receive', onClick: () => activeAccount?.address && handleCopy(activeAccount.address) },
              { icon: ArrowLeftRight, label: 'Swap', onClick: () => setTab('swap') },
              { icon: ShieldCheck, label: 'Protect', onClick: () => setTab('insights') },
            ].map((action) => (
              <button
                key={action.label}
                onClick={action.onClick}
                className="flex flex-col items-center gap-2 rounded-[1.2rem] border border-slate-200 bg-slate-50 px-2 py-3 text-center transition-colors hover:border-slate-300 hover:bg-white"
              >
                <div className="flex h-10 w-10 items-center justify-center rounded-full bg-white shadow-sm">
                  <action.icon className="h-5 w-5 text-blue-700" />
                </div>
                <span className="text-[11px] font-semibold text-slate-700">{action.label}</span>
              </button>
            ))}
          </div>
        </div>

        <div className="mt-5 rounded-[1.7rem] border border-slate-200 bg-slate-50 p-5">
          <div className="flex items-center justify-between gap-4">
            <div>
              <div className="text-xs font-semibold uppercase tracking-[0.18em] text-slate-500">Tracked networks</div>
              <div className="mt-2 text-lg font-bold text-slate-950">Live native balances</div>
            </div>
            <div className="text-xs font-medium text-slate-500">
              {portfolio?.refreshedAt ? `Updated ${new Date(portfolio.refreshedAt).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' })}` : 'Waiting for first refresh'}
            </div>
          </div>

          <div className="mt-4 space-y-3">
            {(portfolio?.chains ?? []).map((chain) => (
              <div
                key={chain.chainId}
                className="flex items-center justify-between gap-4 rounded-[1.4rem] border border-white bg-white px-4 py-4"
              >
                <div>
                  <div className="flex items-center gap-2">
                    <div className="text-sm font-semibold text-slate-950">{chain.name}</div>
                    <span
                      className={cn(
                        'rounded-full px-2.5 py-1 text-[10px] font-semibold uppercase tracking-[0.18em]',
                        chain.status === 'ok' ? 'bg-emerald-50 text-emerald-700' : 'bg-amber-50 text-amber-700'
                      )}
                    >
                      {chain.status}
                    </span>
                  </div>
                  <div className="mt-1 text-xs font-medium text-slate-500">
                    {chain.sourceLabel === 'local-node' ? 'Local node' : 'PublicNode'} {chain.latestBlock ? `• block ${chain.latestBlock}` : ''}
                  </div>
                  {chain.error ? (
                    <div className="mt-2 text-xs font-medium text-amber-700">{chain.error}</div>
                  ) : null}
                </div>

                <div className="text-right">
                  <div className="text-lg font-bold text-slate-950">
                    {chain.balanceDisplay ? `${chain.balanceDisplay} ${chain.nativeCurrency}` : 'Unavailable'}
                  </div>
                  <a
                    href={`${chain.explorerAddressUrl}${activeAccount?.address ?? ''}`}
                    target="_blank"
                    rel="noreferrer"
                    className="mt-2 inline-flex items-center gap-1 text-xs font-semibold text-blue-700 hover:text-blue-800"
                  >
                    Explorer
                    <ExternalLink className="h-3.5 w-3.5" />
                  </a>
                </div>
              </div>
            ))}

            {portfolio && portfolio.chains.length === 0 ? (
              <div className="rounded-[1.4rem] border border-white bg-white px-4 py-4 text-sm text-slate-600">
                No live chain data is available yet for this wallet.
              </div>
            ) : null}
          </div>
        </div>

        <div className="mt-5 grid gap-4 md:grid-cols-2">
          <div className="rounded-[1.7rem] border border-slate-200 bg-slate-50 p-5">
            <div className="text-xs font-semibold uppercase tracking-[0.18em] text-slate-500">Execution mode</div>
            <div className="mt-3 text-lg font-bold text-slate-950">Private-ready</div>
            <p className="mt-2 text-sm leading-7 text-slate-600">
              The wallet is configured to prefer cleaner transaction handling when the connected backend supports it.
            </p>
          </div>
          <div className="rounded-[1.7rem] border border-slate-200 bg-slate-50 p-5">
            <div className="text-xs font-semibold uppercase tracking-[0.18em] text-slate-500">Wallet address</div>
            <div className="mt-3 font-mono text-sm text-slate-700 break-all">{activeAccount?.address ?? 'No active account'}</div>
            {activeAccount?.address ? (
              <button
                onClick={() => {
                  void handleCopy(activeAccount.address);
                }}
                className="mt-4 inline-flex items-center gap-2 rounded-full border border-slate-200 bg-white px-4 py-2 text-sm font-semibold text-slate-700 transition-colors hover:border-slate-300"
              >
                <Copy className="h-4 w-4" />
                Copy address
              </button>
            ) : null}
          </div>
        </div>
      </div>
    </motion.div>
  );
}
