import { useState } from 'react';
import { Capacitor } from '@capacitor/core';
import { motion, AnimatePresence } from 'motion/react';
import { Wallet, getAddress } from 'ethers';
import { useAppStore, NFT } from '../../store/appStore';
import { Search, Filter, ExternalLink, X, Info } from 'lucide-react';
import { broadcastSignedSend, prepareNftSend } from '../../lib/api';
import { openExternalUrl } from '../../lib/external';

export function NFTGalleryTab() {
  const isNativePlatform = Capacitor.isNativePlatform();
  const ScreenWrapper: any = isNativePlatform ? 'div' : motion.div;
  const CardWrapper: any = isNativePlatform ? 'div' : motion.div;
  const OverlayWrapper: any = isNativePlatform ? 'div' : motion.div;
  const ModalWrapper: any = isNativePlatform ? 'div' : motion.div;
  const nfts = useAppStore((state) => state.nfts);
  const activeChainKey = useAppStore((state) => state.activeChainKey);
  const accounts = useAppStore((state) => state.accounts);
  const activeAccountId = useAppStore((state) => state.activeAccountId);
  const exportActivePrivateKey = useAppStore((state) => state.exportActivePrivateKey);
  const buildWalletAuth = useAppStore((state) => state.buildWalletAuth);
  const refreshWalletData = useAppStore((state) => state.refreshWalletData);
  const activeAccount = accounts.find((account) => account.id === activeAccountId);

  const [searchQuery, setSearchQuery] = useState('');
  const [selectedNFT, setSelectedNFT] = useState<NFT | null>(null);
  const [recipient, setRecipient] = useState('');
  const [showSendForm, setShowSendForm] = useState(false);
  const [errorMessage, setErrorMessage] = useState<string | null>(null);
  const [explorerUrl, setExplorerUrl] = useState('');
  const [isPreparing, setIsPreparing] = useState(false);
  const [isBroadcasting, setIsBroadcasting] = useState(false);

  const filteredNFTs = nfts.filter(
    (nft) =>
      nft.name.toLowerCase().includes(searchQuery.toLowerCase()) ||
      nft.collection.toLowerCase().includes(searchQuery.toLowerCase()),
  );

  const resetComposer = () => {
    setRecipient('');
    setShowSendForm(false);
    setErrorMessage(null);
    setExplorerUrl('');
  };

  const handleSendNft = async () => {
    if (!selectedNFT || !activeAccount) {
      setErrorMessage('No NFT is selected');
      return;
    }

    setIsPreparing(true);
    setErrorMessage(null);
    try {
      const normalizedRecipient = getAddress(recipient.trim());
      const preparation = await prepareNftSend({
        chainKey: activeChainKey,
        from: activeAccount.address,
        to: normalizedRecipient,
        contractAddress: selectedNFT.contractAddress,
        tokenId: selectedNFT.tokenId,
      });

      setIsPreparing(false);
      setIsBroadcasting(true);

      const privateKey = await exportActivePrivateKey();
      const wallet = new Wallet(privateKey);
      const rawTransaction = await wallet.signTransaction({
        chainId: preparation.chainId,
        nonce: preparation.nonce,
        type: 2,
        to: preparation.contractAddress,
        data: preparation.data,
        value: 0n,
        gasLimit: BigInt(preparation.gasLimit),
        maxFeePerGas: BigInt(preparation.maxFeePerGas),
        maxPriorityFeePerGas: BigInt(preparation.maxPriorityFeePerGas),
      });

      const auth = await buildWalletAuth('send_broadcast', {
        walletAddress: activeAccount.address,
        chainKey: activeChainKey,
      });
      const response = await broadcastSignedSend({
        chainKey: activeChainKey,
        rawTransaction,
        walletAddress: activeAccount.address,
        auth: auth || undefined,
        txType: 'send',
        title: `Send ${selectedNFT.collection}`,
        amount: '-1 NFT',
        fiatAmount: '$0.00',
        asset: selectedNFT.collection,
        to: normalizedRecipient,
        fee: `$${preparation.estimatedFeeUsd.toFixed(2)}`,
      });

      setExplorerUrl(response.explorerUrl);
      await refreshWalletData();
    } catch (error) {
      setErrorMessage(error instanceof Error ? error.message : 'Failed to send NFT');
    } finally {
      setIsPreparing(false);
      setIsBroadcasting(false);
    }
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
      <div className="p-6 pb-4 sticky top-0 bg-zinc-950/80 backdrop-blur-xl z-10 border-b border-white/5">
        <div className="flex items-center justify-between mb-4">
          <h2 className="text-2xl font-semibold tracking-tight">NFT Gallery</h2>
          <div className="flex gap-2">
            <button
              onClick={() => {
                setSearchQuery('');
                setSelectedNFT(null);
                resetComposer();
              }}
              className="w-10 h-10 bg-zinc-900 border border-white/5 rounded-full flex items-center justify-center hover:bg-zinc-800 transition-colors"
            >
              <Filter className="w-5 h-5 text-zinc-400" />
            </button>
          </div>
        </div>

        <div className="relative">
          <Search className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-zinc-500" />
          <input
            type="text"
            placeholder="Search collection or name..."
            value={searchQuery}
            onChange={(e) => setSearchQuery(e.target.value)}
            className="w-full bg-zinc-900 border border-white/5 rounded-xl py-2.5 pl-10 pr-4 text-sm text-white placeholder:text-zinc-600 focus:outline-none focus:border-indigo-500/50 transition-colors"
          />
        </div>
      </div>

      <div className="px-6 py-4">
        {filteredNFTs.length > 0 ? (
          <div className="grid grid-cols-2 gap-4">
            {filteredNFTs.map((nft) => (
              <CardWrapper
                key={nft.id}
                {...(!isNativePlatform ? { layoutId: `nft-${nft.id}` } : {})}
                onClick={() => {
                  resetComposer();
                  setSelectedNFT(nft);
                }}
                className="bg-zinc-900 border border-white/5 rounded-2xl overflow-hidden group cursor-pointer hover:border-white/10 transition-all"
              >
                <div className="aspect-square relative overflow-hidden">
                  <img
                    src={nft.image}
                    alt={nft.name}
                    referrerPolicy="no-referrer"
                    loading="lazy"
                    decoding="async"
                    className="w-full h-full object-cover group-hover:scale-110 transition-transform duration-500"
                  />
                  <div className="absolute top-2 right-2 bg-black/60 backdrop-blur-md px-2 py-1 rounded-lg text-[10px] font-bold text-white border border-white/10">
                    {nft.price}
                  </div>
                </div>
                <div className="p-3">
                  <div className="text-[10px] text-zinc-500 font-medium uppercase tracking-wider mb-0.5 truncate">
                    {nft.collection}
                  </div>
                  <div className="text-sm font-semibold text-white truncate">{nft.name}</div>
                </div>
              </CardWrapper>
            ))}
          </div>
        ) : (
          <div className="flex flex-col items-center justify-center py-20 text-center">
            <div className="w-16 h-16 bg-zinc-900 rounded-full flex items-center justify-center mb-4">
              <Search className="w-8 h-8 text-zinc-700" />
            </div>
            <h3 className="text-lg font-semibold text-white mb-1">No NFTs found</h3>
            <p className="text-sm text-zinc-500">Try searching for something else</p>
          </div>
        )}
      </div>

      <AnimatePresence>
        {selectedNFT && (
          <>
            <OverlayWrapper
              {...(!isNativePlatform
                ? {
                    initial: { opacity: 0 },
                    animate: { opacity: 1 },
                    exit: { opacity: 0 },
                  }
                : {})}
              onClick={() => {
                setSelectedNFT(null);
                resetComposer();
              }}
              className="fixed inset-0 bg-black/80 backdrop-blur-md z-50"
            />
            <ModalWrapper
              {...(!isNativePlatform ? { layoutId: `nft-${selectedNFT.id}` } : {})}
              className="fixed inset-x-4 top-[10%] bottom-[10%] bg-zinc-950 border border-white/10 rounded-[32px] overflow-hidden z-50 flex flex-col"
            >
              <div className="relative flex-1">
                <img
                  src={selectedNFT.image}
                  alt={selectedNFT.name}
                  referrerPolicy="no-referrer"
                  loading="lazy"
                  decoding="async"
                  className="w-full h-full object-cover"
                />
                <button
                  onClick={() => {
                    setSelectedNFT(null);
                    resetComposer();
                  }}
                  className="absolute top-4 right-4 w-10 h-10 bg-black/40 backdrop-blur-md border border-white/10 rounded-full flex items-center justify-center text-white hover:bg-black/60 transition-colors"
                >
                  <X className="w-5 h-5" />
                </button>
              </div>

              <div className="p-6 bg-zinc-950 overflow-y-auto">
                <div className="flex items-center justify-between mb-2">
                  <span className="text-xs font-bold text-indigo-400 uppercase tracking-widest">
                    {selectedNFT.collection}
                  </span>
                  <div className="flex gap-2">
                    <button
                      onClick={() => void openExternalUrl(selectedNFT.externalUrl)}
                      className="p-2 bg-zinc-900 rounded-full text-zinc-400 hover:text-white transition-colors"
                    >
                      <ExternalLink className="w-4 h-4" />
                    </button>
                    <button
                      onClick={() => void openExternalUrl(selectedNFT.explorerUrl)}
                      className="p-2 bg-zinc-900 rounded-full text-zinc-400 hover:text-white transition-colors"
                    >
                      <Info className="w-4 h-4" />
                    </button>
                  </div>
                </div>

                <h3 className="text-2xl font-bold text-white mb-4">{selectedNFT.name}</h3>

                <div className="bg-zinc-900 border border-white/5 rounded-2xl p-4 mb-6">
                  <div className="text-xs text-zinc-500 font-medium mb-1 uppercase tracking-wider">
                    Current Status
                  </div>
                  <div className="flex items-baseline gap-2">
                    <div className="text-2xl font-bold text-white">{selectedNFT.price}</div>
                    <div className="text-sm text-zinc-500 font-medium">
                      {selectedNFT.priceFiat || 'Owned in wallet'}
                    </div>
                  </div>
                </div>

                {errorMessage && <p className="mb-4 text-sm text-red-400">{errorMessage}</p>}
                {explorerUrl && (
                  <a
                    href={explorerUrl}
                    target="_blank"
                    rel="noreferrer"
                    onClick={(event) => {
                      event.preventDefault();
                      void openExternalUrl(explorerUrl);
                    }}
                    className="mb-4 flex items-center justify-center gap-2 rounded-2xl border border-indigo-500/20 bg-indigo-500/10 py-3 text-sm font-medium text-indigo-300"
                  >
                    View transfer on Explorer
                    <ExternalLink className="w-4 h-4" />
                  </a>
                )}

                <div className="flex gap-3">
                  <button
                    onClick={() => void openExternalUrl(selectedNFT.externalUrl)}
                    className="flex-1 bg-white text-black font-bold py-4 rounded-2xl hover:bg-zinc-200 transition-colors"
                  >
                    List for Sale
                  </button>
                  <button
                    onClick={() => {
                      setShowSendForm((current) => !current);
                      setErrorMessage(null);
                    }}
                    className="flex-1 bg-zinc-900 text-white font-bold py-4 rounded-2xl border border-white/5 hover:bg-zinc-800 transition-colors"
                  >
                    Send NFT
                  </button>
                </div>

                {showSendForm && (
                  <div className="mt-4 rounded-2xl border border-white/5 bg-zinc-900 p-4">
                    <label className="mb-2 block text-xs font-bold uppercase tracking-widest text-zinc-500">
                      Recipient
                    </label>
                    <input
                      value={recipient}
                      onChange={(event) => setRecipient(event.target.value)}
                      placeholder="0x..."
                      className="mb-3 w-full rounded-xl border border-white/10 bg-zinc-950 px-4 py-3 text-sm text-white placeholder:text-zinc-600 focus:outline-none focus:border-indigo-500/50"
                    />
                    <div className="flex gap-3">
                      <button
                        onClick={() => {
                          setShowSendForm(false);
                          setRecipient('');
                          setErrorMessage(null);
                        }}
                        className="flex-1 rounded-xl bg-zinc-950 py-3 text-sm font-medium text-white"
                      >
                        Cancel
                      </button>
                      <button
                        onClick={() => void handleSendNft()}
                        disabled={!recipient.trim() || isPreparing || isBroadcasting}
                        className="flex-1 rounded-xl bg-indigo-500 py-3 text-sm font-medium text-white disabled:opacity-50"
                      >
                        {isPreparing ? 'Preparing...' : isBroadcasting ? 'Broadcasting...' : 'Confirm Send'}
                      </button>
                    </div>
                  </div>
                )}
              </div>
            </ModalWrapper>
          </>
        )}
      </AnimatePresence>
    </ScreenWrapper>
  );
}
