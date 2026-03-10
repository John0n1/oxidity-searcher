import { useEffect, useMemo, useState } from 'react';
import { motion, AnimatePresence } from 'motion/react';
import { useAppStore, Token } from '../store/appStore';
import { Search, Plus, ArrowLeft, Check, AlertCircle, X } from 'lucide-react';
import { cn } from '../utils/cn';
import { TokenLogo } from '../components/TokenLogo';
import { getCatalog } from '../lib/api';

export function TokenManagementView() {
  const setView = useAppStore((state) => state.setView);
  const customTokens = useAppStore((state) => state.customTokens);
  const addCustomToken = useAppStore((state) => state.addCustomToken);
  const resolveAndAddCustomToken = useAppStore((state) => state.resolveAndAddCustomToken);
  const activeChainKey = useAppStore((state) => state.activeChainKey);

  const [searchQuery, setSearchQuery] = useState('');
  const [customAddress, setCustomAddress] = useState('');
  const [isAddingCustom, setIsAddingCustom] = useState(false);
  const [popularTokens, setPopularTokens] = useState<Omit<Token, 'balance' | 'fiatBalance'>[]>([]);
  const [isCatalogLoading, setIsCatalogLoading] = useState(true);
  const [isAddingAddress, setIsAddingAddress] = useState(false);
  const [errorMessage, setErrorMessage] = useState<string | null>(null);

  useEffect(() => {
    let cancelled = false;

    const loadCatalog = async () => {
      setIsCatalogLoading(true);
      setErrorMessage(null);
      try {
        const catalog = await getCatalog();
        if (cancelled) {
          return;
        }
        const activeCatalog = catalog.find((entry) => entry.chainKey === activeChainKey);
        setPopularTokens(
          (activeCatalog?.tokens || []).map((token) => ({
            id: `${activeChainKey}:${token.address.toLowerCase()}`,
            chainKey: activeChainKey,
            symbol: token.symbol,
            name: token.name,
            address: token.address,
            logo: token.logo,
            receiveAddress: token.address,
          })),
        );
      } catch (error) {
        if (!cancelled) {
          setErrorMessage(error instanceof Error ? error.message : 'Failed to load token catalog');
        }
      } finally {
        if (!cancelled) {
          setIsCatalogLoading(false);
        }
      }
    };

    void loadCatalog();

    return () => {
      cancelled = true;
    };
  }, [activeChainKey]);

  const filteredPopular = useMemo(() => {
    return popularTokens.filter((token) => 
      token.name.toLowerCase().includes(searchQuery.toLowerCase()) ||
      token.symbol.toLowerCase().includes(searchQuery.toLowerCase())
    );
  }, [popularTokens, searchQuery]);

  const handleAddToken = (token: Omit<Token, 'balance' | 'fiatBalance'>) => {
    if (
      customTokens.some(
        (candidate) =>
          candidate.chainKey === activeChainKey &&
          candidate.address.toLowerCase() === token.address.toLowerCase(),
      )
    ) {
      return;
    }
    
    addCustomToken({
      ...token,
      chainKey: activeChainKey,
      balance: '0.00',
      fiatBalance: '0.00',
    });
  };

  const handleAddCustomByAddress = async () => {
    if (!customAddress.startsWith('0x') || customAddress.length < 42) {
      return;
    }

    setIsAddingAddress(true);
    setErrorMessage(null);
    try {
      await resolveAndAddCustomToken(customAddress.trim());
      setCustomAddress('');
      setIsAddingCustom(false);
    } catch (error) {
      setErrorMessage(error instanceof Error ? error.message : 'Failed to add custom token');
    } finally {
      setIsAddingAddress(false);
    }
  };

  return (
    <motion.div
      initial={{ opacity: 0, x: 20 }}
      animate={{ opacity: 1, x: 0 }}
      exit={{ opacity: 0, x: -20 }}
      className="absolute inset-0 flex flex-col overflow-hidden overscroll-none bg-zinc-950"
    >
      {/* Header */}
      <div className="p-6 border-b border-white/5 flex items-center gap-4">
        <button 
          onClick={() => setView('main')}
          className="w-10 h-10 bg-zinc-900 border border-white/5 rounded-full flex items-center justify-center text-zinc-400 hover:text-white transition-colors"
        >
          <ArrowLeft className="w-5 h-5" />
        </button>
        <h2 className="text-xl font-semibold tracking-tight">Manage Tokens</h2>
      </div>

      <div className="flex-1 overflow-x-hidden overflow-y-auto overscroll-y-contain p-6 space-y-8">
        {/* Search Bar */}
        <div className="space-y-4">
          <div className="relative">
            <Search className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-zinc-500" />
            <input
              type="text"
              placeholder="Search by name or symbol..."
              value={searchQuery}
              onChange={(e) => setSearchQuery(e.target.value)}
              className="w-full bg-zinc-900 border border-white/5 rounded-xl py-3 pl-10 pr-4 text-sm text-white placeholder:text-zinc-600 focus:outline-none focus:border-indigo-500/50 transition-colors"
            />
          </div>
          
          <button 
            onClick={() => setIsAddingCustom(true)}
            className="w-full flex items-center justify-center gap-2 bg-indigo-500/10 border border-indigo-500/20 text-indigo-400 font-medium py-3 rounded-xl hover:bg-indigo-500/20 transition-colors"
          >
            <Plus className="w-4 h-4" />
            Add Custom Token by Address
          </button>
        </div>

        {/* Popular Tokens */}
        <div>
          <h3 className="text-sm font-bold text-zinc-500 uppercase tracking-widest mb-4">Popular Tokens</h3>
          <div className="space-y-3">
            {isCatalogLoading && (
              <div className="text-sm text-zinc-500 px-1">Loading token catalog...</div>
            )}
            {!isCatalogLoading && filteredPopular.length === 0 && (
              <div className="text-sm text-zinc-500 px-1">No tokens match your search.</div>
            )}
            {filteredPopular.map((token) => {
              const isAdded = customTokens.some(
                (candidate) =>
                  candidate.chainKey === activeChainKey &&
                  candidate.address.toLowerCase() === token.address.toLowerCase(),
              );
              return (
                <div 
                  key={token.id}
                  className="bg-zinc-900 border border-white/5 rounded-2xl p-4 flex items-center justify-between gap-4 hover:border-white/10 transition-colors"
                >
                  <div className="flex min-w-0 items-center gap-4">
                    <TokenLogo 
                      logo={token.logo} 
                      symbol={token.symbol} 
                      address={token.address} 
                    />
                    <div className="min-w-0">
                      <div className="font-semibold text-white">{token.symbol}</div>
                      <div className="truncate text-xs text-zinc-500">{token.name}</div>
                    </div>
                  </div>
                  <button 
                    onClick={() => handleAddToken(token)}
                    disabled={isAdded}
                    className={cn(
                      "w-10 h-10 rounded-full flex items-center justify-center transition-all",
                      isAdded 
                        ? "bg-emerald-500/10 text-emerald-500" 
                        : "bg-zinc-800 text-zinc-400 hover:bg-zinc-700 hover:text-white"
                    )}
                  >
                    {isAdded ? <Check className="w-5 h-5" /> : <Plus className="w-5 h-5" />}
                  </button>
                </div>
              );
            })}
          </div>
        </div>
        {errorMessage && (
          <p className="text-sm text-red-400">{errorMessage}</p>
        )}

        {/* Custom Tokens List */}
        {customTokens.length > 0 && (
          <div>
            <h3 className="text-sm font-bold text-zinc-500 uppercase tracking-widest mb-4">Your Custom Tokens</h3>
            <div className="space-y-3">
              {customTokens.map((token) => (
                <div 
                  key={token.id}
                  className="bg-zinc-900 border border-white/5 rounded-2xl p-4 flex items-center justify-between gap-4"
                >
                  <div className="flex min-w-0 items-center gap-4">
                    <TokenLogo 
                      logo={token.logo} 
                      symbol={token.symbol} 
                      address={token.address} 
                    />
                    <div className="min-w-0">
                      <div className="font-semibold text-white">{token.symbol}</div>
                      <div className="truncate text-[10px] text-zinc-500 font-mono">{token.address}</div>
                    </div>
                  </div>
                  <div className="text-right">
                    <div className="text-sm font-medium text-white">{token.balance} {token.symbol}</div>
                    <div className="text-[10px] text-zinc-500">${token.fiatBalance}</div>
                  </div>
                </div>
              ))}
            </div>
          </div>
        )}
      </div>

      {/* Add Custom Modal */}
      <AnimatePresence>
        {isAddingCustom && (
          <>
            <motion.div
              initial={{ opacity: 0 }}
              animate={{ opacity: 1 }}
              exit={{ opacity: 0 }}
              onClick={() => setIsAddingCustom(false)}
              className="fixed inset-0 bg-black/60 backdrop-blur-sm z-50"
            />
            <motion.div
              initial={{ opacity: 0, scale: 0.9 }}
              animate={{ opacity: 1, scale: 1 }}
              exit={{ opacity: 0, scale: 0.9 }}
              className="fixed top-1/2 left-1/2 -translate-x-1/2 -translate-y-1/2 w-[90%] max-w-md bg-zinc-950 border border-white/10 rounded-[32px] p-8 z-50"
            >
              <div className="flex items-center justify-between mb-6">
                <h3 className="text-xl font-semibold">Add Custom Token</h3>
                <button onClick={() => setIsAddingCustom(false)} className="p-2 bg-zinc-900 rounded-full text-zinc-400 hover:text-white transition-colors">
                  <X className="w-5 h-5" />
                </button>
              </div>

              <div className="space-y-6">
                <div className="bg-amber-500/10 border border-amber-500/20 rounded-2xl p-4 flex gap-3">
                  <AlertCircle className="w-5 h-5 text-amber-500 shrink-0" />
                  <p className="text-xs text-amber-200/70 leading-relaxed">
                    Anyone can create a token, including fake versions of existing tokens. Always verify the contract address before adding.
                  </p>
                </div>

                <div className="space-y-2">
                  <label className="text-xs font-bold text-zinc-500 uppercase tracking-widest ml-1">Contract Address</label>
                  <input
                    type="text"
                    placeholder="0x..."
                    value={customAddress}
                    onChange={(e) => setCustomAddress(e.target.value)}
                    className="w-full bg-zinc-900 border border-white/5 rounded-xl py-4 px-4 text-sm text-white placeholder:text-zinc-600 focus:outline-none focus:border-indigo-500/50 transition-colors font-mono"
                  />
                </div>

                <button 
                  onClick={() => void handleAddCustomByAddress()}
                  disabled={!customAddress.startsWith('0x') || customAddress.length < 42 || isAddingAddress}
                  className="w-full bg-white text-black font-bold py-4 rounded-2xl hover:bg-zinc-200 transition-colors disabled:opacity-50 disabled:cursor-not-allowed"
                >
                  {isAddingAddress ? 'Resolving Token...' : 'Add Token'}
                </button>
              </div>
            </motion.div>
          </>
        )}
      </AnimatePresence>
    </motion.div>
  );
}
