import { useState } from 'react';
import { Capacitor } from '@capacitor/core';
import { motion } from 'motion/react';
import { ArrowLeft, Plus, Trash2, Search, User } from 'lucide-react';
import { useAppStore } from '../store/appStore';

export function AddressBookView() {
  const setView = useAppStore((state) => state.setView);
  const addressBook = useAppStore((state) => state.addressBook);
  const addAddressBookEntry = useAppStore((state) => state.addAddressBookEntry);
  const removeAddressBookEntry = useAppStore((state) => state.removeAddressBookEntry);
  const activeChainKey = useAppStore((state) => state.activeChainKey);
  const isNativePlatform = Capacitor.isNativePlatform();
  const ScreenWrapper: any = isNativePlatform ? 'div' : motion.div;
  const [searchQuery, setSearchQuery] = useState('');
  const [isAdding, setIsAdding] = useState(false);
  const [newName, setNewName] = useState('');
  const [newAddress, setNewAddress] = useState('');
  const [errorMessage, setErrorMessage] = useState<string | null>(null);

  const visibleEntries = addressBook.filter((entry) => entry.chainKey === activeChainKey);
  const filteredEntries = visibleEntries.filter(entry => 
    entry.name.toLowerCase().includes(searchQuery.toLowerCase()) ||
    entry.address.toLowerCase().includes(searchQuery.toLowerCase())
  );

  const handleAdd = () => {
    if (newName && newAddress) {
      try {
        addAddressBookEntry({ name: newName.trim(), address: newAddress });
        setIsAdding(false);
        setNewName('');
        setNewAddress('');
        setErrorMessage(null);
      } catch (error) {
        setErrorMessage(error instanceof Error ? error.message : 'Invalid address');
      }
    }
  };

  return (
    <ScreenWrapper
      {...(!isNativePlatform
        ? {
            initial: { opacity: 0, x: 20 },
            animate: { opacity: 1, x: 0 },
            exit: { opacity: 0, x: -20 },
          }
        : {})}
      className="absolute inset-0 bg-zinc-950 flex flex-col"
    >
      <div className="p-6 pb-4 border-b border-white/5 space-y-4">
        <div className="flex items-center justify-between">
          <button 
            onClick={() => {
              useAppStore.getState().setTab('settings');
              setView('main');
            }}
            className="w-10 h-10 bg-zinc-900 border border-white/5 rounded-full flex items-center justify-center hover:bg-zinc-800 transition-colors"
          >
            <ArrowLeft className="w-5 h-5 text-white" />
          </button>
          <h2 className="text-xl font-semibold text-white">Address Book</h2>
          <button 
            onClick={() => setIsAdding(true)}
            className="w-10 h-10 bg-indigo-500/10 border border-indigo-500/20 rounded-full flex items-center justify-center hover:bg-indigo-500/20 transition-colors"
          >
            <Plus className="w-5 h-5 text-indigo-400" />
          </button>
        </div>

        {!isAdding && visibleEntries.length > 0 && (
          <div className="relative">
            <Search className="absolute left-3 top-1/2 -translate-y-1/2 w-5 h-5 text-zinc-500" />
            <input
              type="text"
              placeholder="Search addresses..."
              value={searchQuery}
              onChange={(e) => setSearchQuery(e.target.value)}
              className="w-full bg-zinc-900 border border-white/10 rounded-2xl py-3 pl-10 pr-4 text-white placeholder:text-zinc-500 focus:outline-none focus:border-indigo-500/50 transition-colors"
            />
          </div>
        )}
      </div>

      <div className="flex-1 overflow-y-auto p-6">
        {isAdding ? (
          <div className="space-y-4">
            {errorMessage && <p className="text-sm text-red-400">{errorMessage}</p>}
            <div className="space-y-2">
              <label className="text-sm text-zinc-400">Name</label>
              <input
                type="text"
                value={newName}
                onChange={(e) => setNewName(e.target.value)}
                placeholder="e.g. Alice's Wallet"
                className="w-full bg-zinc-900 border border-white/10 rounded-2xl py-3 px-4 text-white placeholder:text-zinc-500 focus:outline-none focus:border-indigo-500/50 transition-colors"
              />
            </div>
            <div className="space-y-2">
              <label className="text-sm text-zinc-400">Address</label>
              <input
                type="text"
                value={newAddress}
                onChange={(e) => setNewAddress(e.target.value)}
                placeholder={activeChainKey === 'solana' ? 'Solana address' : '0x...'}
                className="w-full bg-zinc-900 border border-white/10 rounded-2xl py-3 px-4 text-white placeholder:text-zinc-500 focus:outline-none focus:border-indigo-500/50 transition-colors font-mono text-sm"
              />
            </div>
            <div className="flex gap-4 pt-4">
              <button 
                onClick={() => setIsAdding(false)}
                className="flex-1 py-3 bg-zinc-900 hover:bg-zinc-800 text-white font-medium rounded-xl transition-colors"
              >
                Cancel
              </button>
              <button 
                onClick={handleAdd}
                disabled={!newName || !newAddress}
                className="flex-1 py-3 bg-indigo-600 hover:bg-indigo-700 disabled:opacity-50 disabled:cursor-not-allowed text-white font-medium rounded-xl transition-colors"
              >
                Save
              </button>
            </div>
          </div>
        ) : visibleEntries.length === 0 ? (
          <div className="flex flex-col items-center justify-center text-center mt-20">
            <div className="w-20 h-20 bg-zinc-900 border border-white/5 rounded-3xl flex items-center justify-center mb-6">
              <User className="w-10 h-10 text-zinc-500" />
            </div>
            <h3 className="text-xl font-semibold tracking-tight mb-3">No Addresses Saved</h3>
            <p className="text-zinc-400 leading-relaxed max-w-[260px] mb-8">
              Save {activeChainKey === 'solana' ? 'Solana' : 'wallet'} addresses here to easily send tokens to friends and family.
            </p>
            <button 
              onClick={() => setIsAdding(true)}
              className="bg-zinc-900 border border-white/5 text-white font-medium py-3 px-6 rounded-2xl hover:bg-zinc-800 transition-colors flex items-center justify-center gap-2"
            >
              <Plus className="w-5 h-5 text-indigo-400" />
              Add Address
            </button>
          </div>
        ) : (
          <div className="space-y-2">
            {filteredEntries.map(entry => (
              <div
                key={entry.id}
                className="w-full flex items-center justify-between p-4 bg-zinc-900 border border-white/5 rounded-2xl"
              >
                <div className="flex items-center gap-4">
                  <div className="w-10 h-10 bg-indigo-500/10 rounded-full flex items-center justify-center">
                    <User className="w-5 h-5 text-indigo-400" />
                  </div>
                  <div className="text-left">
                    <div className="font-semibold text-white">{entry.name}</div>
                    <div className="text-sm text-zinc-500 font-mono">{entry.address.slice(0, 6)}...{entry.address.slice(-4)}</div>
                  </div>
                </div>
                <button 
                  onClick={() => removeAddressBookEntry(entry.id)}
                  className="p-2 bg-red-500/10 text-red-400 rounded-lg hover:bg-red-500/20 transition-colors"
                >
                  <Trash2 className="w-4 h-4" />
                </button>
              </div>
            ))}
          </div>
        )}
      </div>
    </ScreenWrapper>
  );
}
