import { useEffect, useMemo, useState } from 'react';
import { Capacitor } from '@capacitor/core';
import { motion } from 'motion/react';
import { ArrowLeft, Search } from 'lucide-react';
import { useAppStore } from '../store/appStore';
import { TokenLogo } from '../components/TokenLogo';
import { getNativeAssetDescriptor } from '../lib/walletDefaults';
import { preloadTokenLogos } from '../lib/tokenLogos';

export function ReceiveView() {
  const isNativePlatform = Capacitor.isNativePlatform();
  const ScreenWrapper: any = isNativePlatform ? 'div' : motion.div;
  const setView = useAppStore((state) => state.setView);
  const setSelectedReceiveToken = useAppStore((state) => state.setSelectedReceiveToken);
  const nativeAsset = useAppStore((state) => state.nativeAsset);
  const customTokens = useAppStore((state) => state.customTokens);
  const activeAccountId = useAppStore((state) => state.activeAccountId);
  const activeChainKey = useAppStore((state) => state.activeChainKey);
  const accounts = useAppStore((state) => state.accounts);
  const [searchQuery, setSearchQuery] = useState('');
  const activeAccount = accounts.find((account) => account.id === activeAccountId);
  const nativePlaceholder = useMemo(
    () => getNativeAssetDescriptor(activeChainKey),
    [activeChainKey],
  );
  const receiveAssets = useMemo(() => {
    if (nativeAsset) {
      return [nativeAsset, ...customTokens];
    }

    if (!nativePlaceholder) {
      return customTokens;
    }

    return [
      {
        id: `${nativePlaceholder.chainKey}:native`,
        symbol: nativePlaceholder.symbol,
        name: nativePlaceholder.name,
        address: nativePlaceholder.address,
        balance: '0',
        fiatBalance: '0.00',
        logo: nativePlaceholder.logo,
        chainKey: nativePlaceholder.chainKey,
        receiveAddress: activeAccount?.address || nativePlaceholder.address,
        isNative: true,
      },
      ...customTokens,
    ];
  }, [activeAccount?.address, customTokens, nativeAsset, nativePlaceholder]);

  useEffect(() => {
    void preloadTokenLogos(receiveAssets);
  }, [receiveAssets]);

  const filteredAssets = receiveAssets.filter((asset) => 
    asset.name.toLowerCase().includes(searchQuery.toLowerCase()) ||
    asset.symbol.toLowerCase().includes(searchQuery.toLowerCase())
  );

  return (
    <ScreenWrapper
      {...(!isNativePlatform
        ? {
            initial: { opacity: 0, x: 20 },
            animate: { opacity: 1, x: 0 },
            exit: { opacity: 0, x: -20 },
          }
        : {})}
      className="absolute inset-0 overflow-x-hidden bg-zinc-950 flex flex-col"
    >
      <div className="p-6 pb-4 border-b border-white/5 space-y-4">
        <div className="flex items-center justify-between">
          <button 
            onClick={() => setView('main')}
            className="w-10 h-10 bg-zinc-900 border border-white/5 rounded-full flex items-center justify-center hover:bg-zinc-800 transition-colors"
          >
            <ArrowLeft className="w-5 h-5 text-white" />
          </button>
          <h2 className="text-xl font-semibold text-white">Receive</h2>
          <div className="w-10" />
        </div>

        <div className="relative">
          <Search className="absolute left-3 top-1/2 -translate-y-1/2 w-5 h-5 text-zinc-500" />
          <input
            type="text"
            placeholder="Search asset to receive..."
            value={searchQuery}
            onChange={(e) => setSearchQuery(e.target.value)}
            className="w-full bg-zinc-900 border border-white/10 rounded-2xl py-3 pl-10 pr-4 text-white placeholder:text-zinc-500 focus:outline-none focus:border-indigo-500/50 transition-colors"
          />
        </div>
      </div>

      <div className="flex-1 overflow-y-auto p-6">
        <div className="space-y-2">
          {filteredAssets.length === 0 && (
            <div className="text-center py-12 text-sm text-zinc-500">
              No receive assets available on this wallet yet.
            </div>
          )}
          {filteredAssets.map((asset) => (
            <button
              key={asset.id}
              onClick={() => {
                setSelectedReceiveToken({
                  ...asset,
                  receiveAddress: activeAccount?.address || asset.receiveAddress || asset.address,
                });
                setView('receive-qr');
              }}
              className="w-full flex items-center justify-between p-4 bg-zinc-900 border border-white/5 rounded-2xl hover:bg-zinc-800 transition-colors"
            >
              <div className="flex items-center gap-4">
                <TokenLogo symbol={asset.symbol} logo={asset.logo} address={asset.address} className="w-10 h-10" />
                <div className="text-left">
                  <div className="font-semibold text-white">{asset.name}</div>
                  <div className="text-sm text-zinc-500">{asset.symbol}</div>
                </div>
              </div>
            </button>
          ))}
        </div>
      </div>
    </ScreenWrapper>
  );
}
