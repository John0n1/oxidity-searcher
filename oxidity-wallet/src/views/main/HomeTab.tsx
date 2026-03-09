import { useState } from 'react';
import { Capacitor } from '@capacitor/core';
import { motion, AnimatePresence } from 'motion/react';
import { useAppStore } from '../../store/appStore';
import { Bell, ChevronDown, Send, ArrowDownToLine, ArrowLeftRight, CreditCard, ShieldCheck, Zap, Coins, Plus, Check, Edit2, X, Sparkles, Network } from 'lucide-react';
import { cn } from '../../utils/cn';
import { TokenLogo } from '../../components/TokenLogo';

function formatUsd(value: number): string {
  return value.toLocaleString('en-US', {
    minimumFractionDigits: 2,
    maximumFractionDigits: 2,
  });
}

export function HomeTab() {
  const isNativePlatform = Capacitor.isNativePlatform();
  const ScreenWrapper: any = isNativePlatform ? 'div' : motion.div;
  const OverlayWrapper: any = isNativePlatform ? 'div' : motion.div;
  const SheetWrapper: any = isNativePlatform ? 'div' : motion.div;
  const accounts = useAppStore((state) => state.accounts);
  const activeAccountId = useAppStore((state) => state.activeAccountId);
  const activeAccount = accounts.find((account) => account.id === activeAccountId);

  const balance = activeAccount?.balance || 0;
  const fiatBalance = activeAccount?.fiatBalance || 0;
  
  const setActiveAccount = useAppStore((state) => state.setActiveAccount);
  const addAccount = useAppStore((state) => state.addAccount);
  const renameAccount = useAppStore((state) => state.renameAccount);
  const setView = useAppStore((state) => state.setView);
  const customTokens = useAppStore((state) => state.customTokens);
  const nativeAsset = useAppStore((state) => state.nativeAsset);
  const insights = useAppStore((state) => state.insights);
  const syncStatus = useAppStore((state) => state.syncStatus);
  const activeChainKey = useAppStore((state) => state.activeChainKey);
  const availableNetworks = useAppStore((state) => state.availableNetworks);
  const setActiveChainKey = useAppStore((state) => state.setActiveChainKey);

  const [isSwitcherOpen, setIsSwitcherOpen] = useState(false);
  const [isNetworkSwitcherOpen, setIsNetworkSwitcherOpen] = useState(false);
  const [editingId, setEditingId] = useState<string | null>(null);
  const [editName, setEditName] = useState('');

  const hasTrackedAssets = (nativeAsset?.rawBalance || 0) > 0 || customTokens.length > 0;
  const assetRows = nativeAsset ? [nativeAsset, ...customTokens] : customTokens;
  const activeNetwork =
    availableNetworks.find((network) => network.key === activeChainKey)
    || availableNetworks[0]
    || null;

  const handleAddAccount = () => {
    void addAccount({
      name: `Wallet ${accounts.length + 1}`,
    });
  };

  const startEditing = (id: string, name: string) => {
    setEditingId(id);
    setEditName(name);
  };

  const saveEdit = () => {
    if (editingId && editName.trim()) {
      renameAccount(editingId, editName.trim());
    }
    setEditingId(null);
  };

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
      className="absolute inset-0 overflow-x-hidden overflow-y-auto overscroll-y-contain pb-24"
    >
      {/* Header */}
      <div className="flex items-center justify-between p-6 pb-4 sticky top-0 bg-zinc-950/80 backdrop-blur-xl z-10 border-b border-white/5">
        <button 
          onClick={() => setIsSwitcherOpen(true)}
          className="flex items-center gap-2 bg-zinc-900 border border-white/5 px-4 py-2 rounded-full hover:bg-zinc-800 transition-colors"
        >
          <div className="w-5 h-5 rounded-full bg-gradient-to-tr from-indigo-500 to-purple-500" />
          <span className="font-medium text-sm">{activeAccount?.name || 'Main Wallet'}</span>
          <ChevronDown className="w-4 h-4 text-zinc-500" />
        </button>

        <button 
          onClick={() => setView('ai')}
          className="w-10 h-10 bg-indigo-500/10 border border-indigo-500/20 rounded-full flex items-center justify-center hover:bg-indigo-500/20 transition-all group mx-2"
        >
          <Sparkles className="w-5 h-5 text-indigo-400 group-hover:scale-110 transition-transform" />
        </button>

        <button
          onClick={() => useAppStore.getState().setTab('activity')}
          className="w-10 h-10 bg-zinc-900 border border-white/5 rounded-full flex items-center justify-center hover:bg-zinc-800 transition-colors relative"
        >
          <Bell className="w-5 h-5 text-zinc-400" />
          <div className="absolute top-2.5 right-2.5 w-2 h-2 bg-indigo-500 rounded-full border-2 border-zinc-900" />
        </button>
      </div>

      {/* Account Switcher Modal */}
      <AnimatePresence>
        {isSwitcherOpen && (
          <>
            <OverlayWrapper
              {...(!isNativePlatform
                ? {
                    initial: { opacity: 0 },
                    animate: { opacity: 1 },
                    exit: { opacity: 0 },
                  }
                : {})}
              onClick={() => setIsSwitcherOpen(false)}
              className="fixed inset-0 bg-black/60 backdrop-blur-sm z-50"
            />
            <SheetWrapper
              {...(!isNativePlatform
                ? {
                    initial: { opacity: 0, y: 100 },
                    animate: { opacity: 1, y: 0 },
                    exit: { opacity: 0, y: 100 },
                  }
                : {})}
              className="fixed bottom-0 left-0 right-0 bg-zinc-950 border-t border-white/10 rounded-t-[40px] p-6 z-50 max-h-[80vh] overflow-y-auto"
            >
              <div className="flex items-center justify-between mb-6">
                <h3 className="text-xl font-semibold tracking-tight">Wallets</h3>
                <button onClick={() => setIsSwitcherOpen(false)} className="p-2 bg-zinc-900 rounded-full text-zinc-400 hover:text-white transition-colors">
                  <X className="w-5 h-5" />
                </button>
              </div>

              <div className="space-y-3 mb-6">
                {accounts.map(account => (
                  <div 
                    key={account.id}
                    className={cn(
                      "flex items-center justify-between p-4 rounded-2xl border transition-colors cursor-pointer",
                      activeAccountId === account.id 
                        ? "bg-indigo-500/10 border-indigo-500/30" 
                        : "bg-zinc-900 border-white/5 hover:bg-zinc-800"
                    )}
                    onClick={() => {
                      if (editingId !== account.id) {
                        setActiveAccount(account.id);
                        setIsSwitcherOpen(false);
                      }
                    }}
                  >
                    <div className="flex items-center gap-4">
                      <div className="w-10 h-10 rounded-full bg-gradient-to-tr from-indigo-500 to-purple-500" />
                      <div className="min-w-0">
                        {editingId === account.id ? (
                          <input
                            autoFocus
                            value={editName}
                            onChange={(e) => setEditName(e.target.value)}
                            onBlur={saveEdit}
                            onKeyDown={(e) => e.key === 'Enter' && saveEdit()}
                            className="bg-zinc-950 border border-indigo-500/50 rounded px-2 py-1 text-sm text-white focus:outline-none w-32"
                            onClick={(e) => e.stopPropagation()}
                          />
                        ) : (
                          <div className="font-medium text-white flex items-center gap-2">
                            {account.name}
                            <button 
                              onClick={(e) => {
                                e.stopPropagation();
                                startEditing(account.id, account.name);
                              }}
                              className="text-zinc-500 hover:text-zinc-300"
                            >
                              <Edit2 className="w-3 h-3" />
                            </button>
                          </div>
                        )}
                        <div className="truncate text-xs text-zinc-500 font-mono mt-0.5">{account.address}</div>
                      </div>
                    </div>
                    {activeAccountId === account.id && (
                      <Check className="w-5 h-5 text-indigo-400" />
                    )}
                  </div>
                ))}
              </div>

              <button 
                onClick={handleAddAccount}
                className="w-full flex items-center justify-center gap-2 bg-zinc-900 border border-white/5 text-white font-medium py-4 rounded-2xl hover:bg-zinc-800 transition-colors"
              >
                <Plus className="w-5 h-5" />
                Add New Wallet
              </button>
            </SheetWrapper>
          </>
        )}
      </AnimatePresence>

      {/* Hero Balance */}
      <div className="px-6 py-6 flex flex-col items-center text-center">
        <div className="text-zinc-400 text-sm font-medium mb-2 uppercase tracking-wider">Total Balance</div>
        <div className="text-5xl font-semibold tracking-tight mb-2 flex items-baseline gap-1">
          <span className="text-zinc-500">$</span>
          <span>{fiatBalance > 0 ? formatUsd(fiatBalance) : '0.00'}</span>
        </div>
        <button
          onClick={() => setIsNetworkSwitcherOpen(true)}
          className="flex items-center gap-2 bg-emerald-500/10 text-emerald-400 px-3 py-1 rounded-full text-sm font-medium border border-emerald-500/20"
        >
          <Network className="w-4 h-4" />
          {syncStatus === 'loading'
            ? 'Syncing portfolio...'
            : `${activeNetwork?.name || activeChainKey.toUpperCase()} · ${insights.privateRoutingPct.toFixed(0)}% private`}
          <ChevronDown className="w-4 h-4 text-emerald-300/70" />
        </button>
      </div>

      {/* Action Row */}
      <div className="px-6 py-4 grid grid-cols-4 gap-4">
        {[
          { icon: Send, label: 'Send', onClick: () => setView('send') },
          { icon: ArrowDownToLine, label: 'Receive', onClick: () => setView('receive') },
          { icon: ArrowLeftRight, label: 'Swap', onClick: () => useAppStore.getState().setTab('swap') },
          { icon: CreditCard, label: 'Buy', onClick: () => setView('buy') },
        ].map((action, i) => (
          <button 
            key={i} 
            onClick={action.onClick}
            className="flex flex-col items-center gap-2 group"
          >
            <div className="w-14 h-14 bg-zinc-900 border border-white/5 rounded-2xl flex items-center justify-center group-hover:bg-zinc-800 group-hover:border-white/10 transition-all">
              <action.icon className="w-6 h-6 text-zinc-300 group-hover:text-white transition-colors" />
            </div>
            <span className="text-xs font-medium text-zinc-400 group-hover:text-zinc-300 transition-colors">{action.label}</span>
          </button>
        ))}
      </div>

      {/* Quick Stats */}
      <div className="px-6 py-4">
        <div className="grid grid-cols-3 gap-3">
          <div className="bg-zinc-900 border border-white/5 rounded-2xl p-4 flex flex-col gap-2">
            <Zap className="w-5 h-5 text-indigo-400" />
            <div>
              <div className="text-xs text-zinc-500 font-medium mb-0.5">Gas Saved</div>
              <div className="text-sm font-semibold text-white">${formatUsd(insights.gasSavedUsd)}</div>
            </div>
          </div>
          <div className="bg-zinc-900 border border-white/5 rounded-2xl p-4 flex flex-col gap-2">
            <Coins className="w-5 h-5 text-amber-400" />
            <div>
              <div className="text-xs text-zinc-500 font-medium mb-0.5">Rebates</div>
              <div className="text-sm font-semibold text-white">${formatUsd(insights.rebatesUsd)}</div>
            </div>
          </div>
          <div className="bg-zinc-900 border border-white/5 rounded-2xl p-4 flex flex-col gap-2">
            <ShieldCheck className="w-5 h-5 text-emerald-400" />
            <div>
              <div className="text-xs text-zinc-500 font-medium mb-0.5">Protected</div>
              <div className="text-sm font-semibold text-white">{insights.protectedTxCount} txs</div>
            </div>
          </div>
        </div>
      </div>

      {/* Assets */}
      <div className="px-6 py-4">
        <div className="flex items-center justify-between mb-4">
          <h3 className="text-lg font-semibold tracking-tight">Assets</h3>
          <button 
            onClick={() => setView('token-management')}
            className="text-sm text-indigo-400 font-medium hover:text-indigo-300 transition-colors"
          >
            Manage
          </button>
        </div>
        
        {!hasTrackedAssets ? (
          <div className="bg-zinc-900 border border-white/5 rounded-3xl p-8 flex flex-col items-center text-center">
            <div className="w-16 h-16 bg-zinc-800 rounded-full flex items-center justify-center mb-4">
              <CreditCard className="w-8 h-8 text-zinc-500" />
            </div>
            <h4 className="font-semibold mb-2">No Assets Yet</h4>
            <p className="text-sm text-zinc-400 mb-6 max-w-[200px]">
              Buy or receive crypto to get started with Oxidity.
            </p>
            <button 
              onClick={() => setView('buy')}
              className="bg-white text-black font-medium px-6 py-3 rounded-xl hover:bg-zinc-200 transition-colors w-full"
            >
              Buy Crypto
            </button>
          </div>
        ) : (
          <div className="space-y-3">
            {assetRows.map((token) => (
              <div 
                key={token.id}
                className="bg-zinc-900 border border-white/5 rounded-2xl p-4 flex items-center justify-between"
              >
                <div className="flex items-center gap-4">
                  <TokenLogo 
                    logo={token.logo} 
                    symbol={token.symbol} 
                    address={token.address} 
                  />
                  <div>
                    <div className="font-semibold text-white">{token.symbol}</div>
                    <div className="text-xs text-zinc-500">{token.name || token.symbol}</div>
                  </div>
                </div>
                <div className="text-right">
                  <div className="text-sm font-medium text-white">{token.balance} {token.symbol}</div>
                  <div className="text-[10px] text-zinc-500">${token.fiatBalance}</div>
                </div>
              </div>
            ))}
          </div>
        )}
      </div>

      <AnimatePresence>
        {isNetworkSwitcherOpen && (
          <>
            <OverlayWrapper
              {...(!isNativePlatform
                ? {
                    initial: { opacity: 0 },
                    animate: { opacity: 1 },
                    exit: { opacity: 0 },
                  }
                : {})}
              onClick={() => setIsNetworkSwitcherOpen(false)}
              className="fixed inset-0 bg-black/60 backdrop-blur-sm z-50"
            />
            <SheetWrapper
              {...(!isNativePlatform
                ? {
                    initial: { opacity: 0, y: 100 },
                    animate: { opacity: 1, y: 0 },
                    exit: { opacity: 0, y: 100 },
                  }
                : {})}
              className="fixed bottom-0 left-0 right-0 bg-zinc-950 border-t border-white/10 rounded-t-[40px] p-6 z-50 max-h-[80vh] overflow-y-auto"
            >
              <div className="flex items-center justify-between mb-6">
                <div>
                  <h3 className="text-xl font-semibold tracking-tight">Networks</h3>
                  <p className="text-sm text-zinc-500">Switch the active network for this wallet.</p>
                </div>
                <button
                  onClick={() => setIsNetworkSwitcherOpen(false)}
                  className="p-2 bg-zinc-900 rounded-full text-zinc-400 hover:text-white transition-colors"
                >
                  <X className="w-5 h-5" />
                </button>
              </div>

              <div className="space-y-3">
                {availableNetworks.length === 0 ? (
                  <div className="rounded-2xl border border-white/5 bg-zinc-900 p-4 text-sm text-zinc-500">
                    Network catalog is still loading.
                  </div>
                ) : (
                  availableNetworks.map((network) => (
                    <button
                      key={network.key}
                      onClick={() => {
                        void setActiveChainKey(network.key);
                        setIsNetworkSwitcherOpen(false);
                      }}
                      className={cn(
                        'flex w-full items-center justify-between rounded-2xl border p-4 text-left transition-colors',
                        network.key === activeChainKey
                          ? 'border-indigo-500/30 bg-indigo-500/10'
                          : 'border-white/5 bg-zinc-900 hover:bg-zinc-800',
                      )}
                    >
                      <div>
                        <div className="font-medium text-white">{network.name}</div>
                        <div className="text-xs text-zinc-500 uppercase tracking-wider">
                          {network.status}
                          {network.chainId ? ` • Chain ${network.chainId}` : ''}
                        </div>
                      </div>
                      {network.key === activeChainKey ? (
                        <Check className="w-5 h-5 text-indigo-400" />
                      ) : null}
                    </button>
                  ))
                )}
              </div>
            </SheetWrapper>
          </>
        )}
      </AnimatePresence>
    </ScreenWrapper>
  );
}
