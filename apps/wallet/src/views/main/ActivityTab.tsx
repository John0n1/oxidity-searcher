import { useState, useMemo } from 'react';
import { Capacitor } from '@capacitor/core';
import { motion } from 'motion/react';
import { Activity, ArrowDownToLine, ArrowUpRight, ArrowLeftRight, Shield, Zap, Search, Filter } from 'lucide-react';
import { cn } from '../../utils/cn';

import { useAppStore } from '../../store/appStore';

const FILTERS = ['All', 'Send', 'Receive', 'Swap'];

export function ActivityTab() {
  const activity = useAppStore((state) => state.activity);
  const setView = useAppStore((state) => state.setView);
  const setSelectedTransaction = useAppStore((state) => state.setSelectedTransaction);
  const isNativePlatform = Capacitor.isNativePlatform();
  const ScreenWrapper: any = isNativePlatform ? 'div' : motion.div;
  const [searchQuery, setSearchQuery] = useState('');
  const [activeFilter, setActiveFilter] = useState('All');

  const filteredTxs = useMemo(() => {
    return activity.filter((tx) => {
      const normalizedType = tx.type.charAt(0).toUpperCase() + tx.type.slice(1).toLowerCase();
      const matchesFilter = activeFilter === 'All' || normalizedType === activeFilter;
      const searchLower = searchQuery.toLowerCase();
      const matchesSearch = 
        tx.title.toLowerCase().includes(searchLower) ||
        tx.asset.toLowerCase().includes(searchLower) ||
        tx.address?.toLowerCase().includes(searchLower) ||
        tx.hash?.toLowerCase().includes(searchLower) ||
        tx.to?.toLowerCase().includes(searchLower) ||
        tx.from?.toLowerCase().includes(searchLower) ||
        false;
      
      return matchesFilter && matchesSearch;
    });
  }, [activity, searchQuery, activeFilter]);

  const hasActivity = activity.length > 0;

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
      <div className="p-6 pb-4 sticky top-0 bg-zinc-950/80 backdrop-blur-xl z-10 border-b border-white/5 space-y-4">
        <div className="flex items-center justify-between">
          <h2 className="text-2xl font-semibold tracking-tight">Activity</h2>
          <button
            onClick={() => {
              setSearchQuery('');
              setActiveFilter('All');
            }}
            className="w-10 h-10 bg-zinc-900 border border-white/5 rounded-full flex items-center justify-center hover:bg-zinc-800 transition-colors"
          >
            <Filter className="w-5 h-5 text-zinc-400" />
          </button>
        </div>

        {hasActivity && (
          <>
            {/* Search Bar */}
            <div className="relative">
              <Search className="absolute left-3 top-1/2 -translate-y-1/2 w-5 h-5 text-zinc-500" />
              <input
                type="text"
                placeholder="Search by address or token..."
                value={searchQuery}
                onChange={(e) => setSearchQuery(e.target.value)}
                className="w-full bg-zinc-900 border border-white/10 rounded-2xl py-3 pl-10 pr-4 text-white placeholder:text-zinc-500 focus:outline-none focus:border-indigo-500/50 transition-colors"
              />
            </div>

            {/* Filters */}
            <div className="flex gap-2 overflow-x-auto no-scrollbar pb-1">
              {FILTERS.map(filter => (
                <button
                  key={filter}
                  onClick={() => setActiveFilter(filter)}
                  className={cn(
                    "px-4 py-1.5 rounded-full text-sm font-medium whitespace-nowrap transition-colors border",
                    activeFilter === filter
                      ? "bg-white text-black border-white"
                      : "bg-zinc-900 text-zinc-400 border-white/5 hover:bg-zinc-800 hover:text-zinc-300"
                  )}
                >
                  {filter}
                </button>
              ))}
            </div>
          </>
        )}
      </div>

      <div className="px-6 py-4">
        {!hasActivity ? (
          <div className="flex flex-col items-center justify-center text-center mt-20">
            <div className="w-20 h-20 bg-zinc-900 border border-white/5 rounded-3xl flex items-center justify-center mb-6">
              <Activity className="w-10 h-10 text-zinc-500" />
            </div>
            <h3 className="text-xl font-semibold tracking-tight mb-3">No Activity Yet</h3>
            <p className="text-zinc-400 leading-relaxed max-w-[260px] mb-8">
              Your transactions will appear here. Oxidity protects your trades and saves you gas.
            </p>
            <div className="grid grid-cols-2 gap-4 w-full">
              <button 
                onClick={() => setView('receive')}
                className="bg-zinc-900 border border-white/5 text-white font-medium py-4 rounded-2xl hover:bg-zinc-800 transition-colors flex flex-col items-center justify-center gap-2"
              >
                <ArrowDownToLine className="w-5 h-5 text-indigo-400" />
                Receive
              </button>
              <button 
                onClick={() => useAppStore.getState().setTab('swap')}
                className="bg-zinc-900 border border-white/5 text-white font-medium py-4 rounded-2xl hover:bg-zinc-800 transition-colors flex flex-col items-center justify-center gap-2"
              >
                <ArrowLeftRight className="w-5 h-5 text-emerald-400" />
                Swap
              </button>
            </div>
          </div>
        ) : filteredTxs.length === 0 ? (
          <div className="text-center mt-12 text-zinc-500">
            No transactions found matching your criteria.
          </div>
        ) : (
          <div className="space-y-4">
            {filteredTxs.map((tx) => {
              const normalizedType = tx.type.charAt(0).toUpperCase() + tx.type.slice(1).toLowerCase();
              return (
              <div 
                key={tx.id} 
                onClick={() => {
                  setSelectedTransaction(tx);
                  setView('transaction-details');
                }}
                className="bg-zinc-900 border border-white/5 rounded-2xl p-4 flex items-center gap-4 hover:bg-zinc-800 transition-colors cursor-pointer"
              >
                <div className={cn(
                  "w-12 h-12 rounded-full flex items-center justify-center shrink-0",
                  normalizedType === 'Swap' ? "bg-emerald-500/10" :
                  normalizedType === 'Receive' ? "bg-indigo-500/10" : "bg-amber-500/10"
                )}>
                  {normalizedType === 'Swap' && <ArrowLeftRight className="w-6 h-6 text-emerald-400" />}
                  {normalizedType === 'Receive' && <ArrowDownToLine className="w-6 h-6 text-indigo-400" />}
                  {normalizedType === 'Send' && <ArrowUpRight className="w-6 h-6 text-amber-400" />}
                </div>
                <div className="flex-1 min-w-0">
                  <div className="flex items-center justify-between mb-1">
                    <span className="font-semibold truncate pr-2">{tx.title}</span>
                    <span className={cn(
                      "font-semibold shrink-0",
                      tx.fiatAmount.startsWith('+') ? "text-emerald-400" : "text-white"
                    )}>{tx.fiatAmount}</span>
                  </div>
                  <div className="flex items-center justify-between text-sm">
                    <span className="text-zinc-500 truncate">{tx.date}</span>
                    <span className="text-zinc-500 shrink-0">{tx.amount}</span>
                  </div>
                  {(tx.isProtected || tx.rebate) && (
                    <div className="flex items-center gap-2 mt-2">
                      {tx.isProtected && (
                        <span className="flex items-center gap-1 text-[10px] uppercase font-semibold tracking-wider bg-indigo-500/10 text-indigo-400 px-2 py-0.5 rounded-full">
                          <Shield className="w-3 h-3" /> Protected
                        </span>
                      )}
                      {tx.rebate && (
                        <span className="flex items-center gap-1 text-[10px] uppercase font-semibold tracking-wider bg-amber-500/10 text-amber-400 px-2 py-0.5 rounded-full">
                          <Zap className="w-3 h-3" /> {tx.rebate} Rebate
                        </span>
                      )}
                    </div>
                  )}
                </div>
              </div>
            )})}
          </div>
        )}
      </div>
    </ScreenWrapper>
  );
}
