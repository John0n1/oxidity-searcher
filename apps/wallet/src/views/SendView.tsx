import { useEffect, useMemo, useState } from 'react';
import { Capacitor } from '@capacitor/core';
import { motion, AnimatePresence } from 'motion/react';
import { ArrowLeft, Search, User, ChevronDown, ShieldCheck, Info, Zap, Check, Plus, ExternalLink } from 'lucide-react';
import { Wallet, getAddress, parseEther } from 'ethers';

import { deriveSolanaPrivateKeyFromMnemonic } from '../lib/chainAddresses';
import { openExternalUrl } from '../lib/external';
import { useAppStore } from '../store/appStore';
import { cn } from '../utils/cn';
import { broadcastSignedSend, prepareNativeSend, type SendPrepareResponse } from '../lib/api';
import { TokenLogo } from '../components/TokenLogo';
import { getNativeAssetDescriptor } from '../lib/walletDefaults';
import { preloadTokenLogos } from '../lib/tokenLogos';

type Step = 'address' | 'amount' | 'review' | 'success';
type Speed = 'slow' | 'standard' | 'fast';

const SPEED_LABELS: Record<Speed, { time: string; multiplier: bigint }> = {
  slow: { time: '< 5 min', multiplier: 95n },
  standard: { time: '< 2 min', multiplier: 100n },
  fast: { time: '< 30 sec', multiplier: 125n },
};

function formatUsd(value: number): string {
  return value.toLocaleString('en-US', {
    minimumFractionDigits: 2,
    maximumFractionDigits: 2,
  });
}

function formatAmount(value: number): string {
  const rendered = value.toFixed(6).replace(/\.?0+$/, '');
  return rendered.length > 0 ? rendered : '0';
}

function scaleWei(value: string, multiplier: bigint): bigint {
  return (BigInt(value) * multiplier + 99n) / 100n;
}

function toBase64(bytes: Uint8Array): string {
  let binary = '';
  bytes.forEach((value) => {
    binary += String.fromCharCode(value);
  });
  return btoa(binary);
}

export function SendView() {
  const isNativePlatform = Capacitor.isNativePlatform();
  const ScreenWrapper: any = isNativePlatform ? 'div' : motion.div;
  const setView = useAppStore((state) => state.setView);
  const addressBook = useAppStore((state) => state.addressBook);
  const addAddressBookEntry = useAppStore((state) => state.addAddressBookEntry);
  const accounts = useAppStore((state) => state.accounts);
  const activeAccountId = useAppStore((state) => state.activeAccountId);
  const activeChainKey = useAppStore((state) => state.activeChainKey);
  const nativeAsset = useAppStore((state) => state.nativeAsset);
  const exportActivePrivateKey = useAppStore((state) => state.exportActivePrivateKey);
  const exportActiveRecoveryPhrase = useAppStore((state) => state.exportActiveRecoveryPhrase);
  const buildWalletAuth = useAppStore((state) => state.buildWalletAuth);
  const refreshWalletData = useAppStore((state) => state.refreshWalletData);
  const activeAccount = accounts.find((account) => account.id === activeAccountId);
  const [step, setStep] = useState<Step>('address');
  const [address, setAddress] = useState('');
  const [resolvedAddress, setResolvedAddress] = useState('');
  const [amount, setAmount] = useState('');
  const [speed, setSpeed] = useState<Speed>('standard');
  const [saveName, setSaveName] = useState('');
  const [isSaving, setIsSaving] = useState(false);
  const [errorMessage, setErrorMessage] = useState<string | null>(null);
  const [isPreparing, setIsPreparing] = useState(false);
  const [isBroadcasting, setIsBroadcasting] = useState(false);
  const [preparation, setPreparation] = useState<SendPrepareResponse | null>(null);
  const [explorerUrl, setExplorerUrl] = useState('');

  const nativePlaceholder = useMemo(
    () => getNativeAssetDescriptor(activeChainKey),
    [activeChainKey],
  );
  const displayedNativeAsset = nativeAsset || (nativePlaceholder
    ? {
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
      }
    : null);
  const nativeSymbol = displayedNativeAsset?.symbol || 'ETH';
  const nativeBalance = nativeAsset?.rawBalance ?? activeAccount?.balance ?? 0;
  const nativePrice =
    nativeAsset && nativeAsset.rawBalance > 0
      ? nativeAsset.fiatValue / nativeAsset.rawBalance
      : 0;
  const amountValue = Number(amount);
  const isSolanaChain = activeChainKey === 'solana';

  const gasFees = useMemo(() => {
    const base = preparation?.estimatedFeeUsd || 0;
    return {
      slow: { fiat: Math.max(0, base * 0.9), time: SPEED_LABELS.slow.time },
      standard: { fiat: base, time: SPEED_LABELS.standard.time },
      fast: { fiat: base * 1.25, time: SPEED_LABELS.fast.time },
    };
  }, [preparation]);
  const executionMode = preparation?.executionMode || 'direct';
  const isProtectedExecution = executionMode === 'protected';
  const chainAddressBook = addressBook.filter((entry) => entry.chainKey === activeChainKey);

  useEffect(() => {
    if (!displayedNativeAsset) {
      return;
    }

    void preloadTokenLogos([displayedNativeAsset]);
  }, [displayedNativeAsset]);

  const handleSaveAddress = () => {
    const value = resolvedAddress || address;
    if (saveName && value) {
      addAddressBookEntry({ name: saveName, address: value });
      setIsSaving(false);
      setSaveName('');
    }
  };

  const isAddressSaved = chainAddressBook.some(
    (entry) =>
      entry.address.toLowerCase() === (resolvedAddress || address).trim().toLowerCase(),
  );

  const filteredAddressBook = chainAddressBook.filter(
    (entry) =>
      entry.name.toLowerCase().includes(address.toLowerCase()) ||
      entry.address.toLowerCase().includes(address.toLowerCase()),
  );

  const setAmountByPercent = (percent: number) => {
    const nextValue = nativeBalance * (percent / 100);
    setAmount(formatAmount(nextValue));
  };

  const handleReview = async () => {
    if (!activeAccount) {
      setErrorMessage('No active wallet is available');
      return;
    }

    setIsPreparing(true);
    setErrorMessage(null);
    try {
      const normalizedAddress = isSolanaChain ? address.trim() : getAddress(address.trim());
      if (!Number.isFinite(amountValue) || amountValue <= 0) {
        throw new Error('Enter a valid amount to send');
      }
      if (amountValue > nativeBalance) {
        throw new Error(`Amount exceeds available ${nativeSymbol} balance`);
      }

      const nextPreparation = await prepareNativeSend({
        chainKey: activeChainKey,
        from: activeAccount.address,
        to: normalizedAddress,
        amount: amount.trim(),
      });

      setResolvedAddress(normalizedAddress);
      setPreparation(nextPreparation);
      setStep('review');
    } catch (error) {
      setErrorMessage(error instanceof Error ? error.message : 'Failed to prepare transaction');
    } finally {
      setIsPreparing(false);
    }
  };

  const handleConfirm = async () => {
    if (!activeAccount || !preparation || !resolvedAddress) {
      setErrorMessage('Transaction is not ready to broadcast');
      return;
    }

    setIsBroadcasting(true);
    setErrorMessage(null);
    try {
      let rawTransaction = '';
      let encoding: string | undefined;

      if (preparation.protocol === 'solana') {
        const phrase = await exportActiveRecoveryPhrase();
        const [{ Keypair, PublicKey, SystemProgram, Transaction }] = await Promise.all([
          import('@solana/web3.js'),
        ]);
        const secretKey = deriveSolanaPrivateKeyFromMnemonic(
          phrase,
          activeAccount.derivationIndex || 0,
        );
        const keypair = Keypair.fromSeed(secretKey);
        if (!preparation.recentBlockhash) {
          throw new Error('Missing Solana blockhash');
        }
        const transaction = new Transaction({
          feePayer: keypair.publicKey,
          recentBlockhash: preparation.recentBlockhash,
        });
        transaction.add(
          SystemProgram.transfer({
            fromPubkey: keypair.publicKey,
            toPubkey: new PublicKey(resolvedAddress),
            lamports: Math.round(amountValue * 1_000_000_000),
          }),
        );
        transaction.sign(keypair);
        rawTransaction = toBase64(transaction.serialize());
        encoding = 'base64';
      } else {
        const privateKey = await exportActivePrivateKey();
        const wallet = new Wallet(privateKey);
        const multiplier = SPEED_LABELS[speed].multiplier;
        const maxPriorityFeePerGas = scaleWei(preparation.maxPriorityFeePerGas, multiplier);
        let maxFeePerGas = scaleWei(preparation.maxFeePerGas, multiplier);
        if (maxFeePerGas <= maxPriorityFeePerGas) {
          maxFeePerGas = maxPriorityFeePerGas + 1n;
        }

        rawTransaction = await wallet.signTransaction({
          chainId: preparation.chainId,
          nonce: preparation.nonce,
          type: 2,
          to: resolvedAddress,
          value: parseEther(amount.trim()),
          gasLimit: BigInt(preparation.gasLimit),
          maxFeePerGas,
          maxPriorityFeePerGas,
        });
      }

      const auth = await buildWalletAuth('send_broadcast', {
        walletAddress: activeAccount.address,
        chainKey: activeChainKey,
      });
      const response = await broadcastSignedSend({
        chainKey: activeChainKey,
        rawTransaction,
        walletAddress: activeAccount.address,
        auth: auth || undefined,
        encoding,
        txType: 'send',
        title: `Send ${nativeSymbol}`,
        amount: `-${formatAmount(amountValue)} ${nativeSymbol}`,
        fiatAmount: `-${formatUsd(amountValue * nativePrice)}`,
        asset: nativeSymbol,
        to: resolvedAddress,
        fee: `$${formatUsd(gasFees[speed].fiat)}`,
      });

      setExplorerUrl(response.explorerUrl);
      setStep('success');
      await refreshWalletData();
    } catch (error) {
      setErrorMessage(error instanceof Error ? error.message : 'Failed to send transaction');
    } finally {
      setIsBroadcasting(false);
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
      className="absolute inset-0 overflow-x-hidden bg-zinc-950 flex flex-col"
    >
      <div className="p-6 border-b border-white/5 flex items-center gap-4">
        {step !== 'success' && (
          <button 
            onClick={() => {
              setErrorMessage(null);
              if (step === 'address') {
                setView('main');
              } else if (step === 'review') {
                setStep('amount');
              } else {
                setStep('address');
              }
            }}
            className="w-10 h-10 bg-zinc-900 border border-white/5 rounded-full flex items-center justify-center text-zinc-400 hover:text-white transition-colors"
          >
            <ArrowLeft className="w-5 h-5" />
          </button>
        )}
        <h2 className="text-xl font-semibold tracking-tight">
          {step === 'address' && 'Send to'}
          {step === 'amount' && 'Amount'}
          {step === 'review' && 'Review'}
          {step === 'success' && 'Sent'}
        </h2>
      </div>

      <div className="flex-1 overflow-y-auto p-6">
        {errorMessage && (
          <p className="mb-6 text-sm text-red-400">{errorMessage}</p>
        )}
        <AnimatePresence mode="wait">
          {step === 'address' && (
            <motion.div
              key="address"
              initial={{ opacity: 0, y: 10 }}
              animate={{ opacity: 1, y: 0 }}
              exit={{ opacity: 0, y: -10 }}
              className="space-y-6"
            >
              <div className="relative">
                <Search className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-zinc-500" />
                <input
                  type="text"
                  placeholder="Wallet address"
                  value={address}
                  onChange={(event) => {
                    setAddress(event.target.value);
                    setResolvedAddress('');
                    setErrorMessage(null);
                  }}
                  className="w-full bg-zinc-900 border border-white/5 rounded-xl py-4 pl-10 pr-4 text-sm text-white placeholder:text-zinc-600 focus:outline-none focus:border-indigo-500/50 transition-colors font-mono"
                />
              </div>

              <div>
                <h3 className="text-xs font-bold text-zinc-500 uppercase tracking-widest mb-4 ml-1">
                  {address ? 'Results' : 'Saved Addresses'}
                </h3>
                <div className="space-y-3">
                  {filteredAddressBook.length > 0 ? (
                    filteredAddressBook.map((entry) => (
                      <button
                        key={entry.id}
                        onClick={() => {
                          setAddress(entry.address);
                          setResolvedAddress(entry.address);
                          setStep('amount');
                        }}
                        className="w-full bg-zinc-900 border border-white/5 rounded-2xl p-4 flex items-center gap-4 hover:border-white/10 transition-colors"
                      >
                        <div className="w-10 h-10 rounded-full bg-indigo-500/10 flex items-center justify-center">
                          <User className="w-5 h-5 text-indigo-400" />
                        </div>
                        <div className="text-left">
                          <div className="font-semibold text-white">{entry.name}</div>
                          <div className="text-xs text-zinc-500 font-mono">
                            {entry.address.slice(0, 6)}...{entry.address.slice(-4)}
                          </div>
                        </div>
                      </button>
                    ))
                  ) : address ? (
                    <div className="text-center py-8 text-zinc-500 text-sm">
                      No saved addresses match "{address}"
                    </div>
                  ) : (
                    <div className="text-center py-8 text-zinc-500 text-sm">
                      No saved addresses yet
                    </div>
                  )}
                </div>
              </div>

              <button 
                disabled={!address.trim()}
                onClick={() => setStep('amount')}
                className="w-full bg-white text-black font-bold py-4 rounded-2xl hover:bg-zinc-200 transition-colors disabled:opacity-50"
              >
                Continue
              </button>
            </motion.div>
          )}

          {step === 'amount' && (
            <motion.div
              key="amount"
              initial={{ opacity: 0, y: 10 }}
              animate={{ opacity: 1, y: 0 }}
              exit={{ opacity: 0, y: -10 }}
              className="space-y-8"
            >
              <div className="flex flex-col items-center gap-4 py-8">
                <div className="flex items-center gap-2 bg-zinc-900 border border-white/5 px-4 py-2 rounded-full">
                  <TokenLogo
                    symbol={nativeSymbol}
                    logo={displayedNativeAsset?.logo}
                    address={displayedNativeAsset?.address}
                    className="h-5 w-5"
                  />
                  <span className="font-semibold text-sm">{nativeSymbol}</span>
                  <ChevronDown className="w-4 h-4 text-zinc-500" />
                </div>
                <input
                  type="number"
                  min="0"
                  step="any"
                  placeholder="0"
                  value={amount}
                  onChange={(event) => {
                    setAmount(event.target.value);
                    setErrorMessage(null);
                  }}
                  className="bg-transparent text-6xl font-bold text-white text-center focus:outline-none w-full placeholder:text-zinc-800"
                />
                <div className="text-zinc-500 font-medium">
                  ${formatUsd(Number.isFinite(amountValue) ? amountValue * nativePrice : 0)}
                </div>
                <div className="text-xs text-zinc-500">
                  Available: {formatAmount(nativeBalance)} {nativeSymbol}
                </div>
              </div>

              <div className="grid grid-cols-3 gap-2">
                {[25, 50, 100].map((percent) => (
                  <button
                    key={percent}
                    onClick={() => setAmountByPercent(percent)}
                    className="bg-zinc-900 border border-white/5 rounded-xl py-2 text-xs font-bold text-zinc-400 hover:text-white transition-colors"
                  >
                    {percent}%
                  </button>
                ))}
              </div>

              <button 
                disabled={!amount.trim() || isPreparing}
                onClick={() => void handleReview()}
                className="w-full bg-white text-black font-bold py-4 rounded-2xl hover:bg-zinc-200 transition-colors disabled:opacity-50"
              >
                {isPreparing ? 'Preparing...' : 'Review'}
              </button>
            </motion.div>
          )}

          {step === 'review' && preparation && (
            <motion.div
              key="review"
              initial={{ opacity: 0, y: 10 }}
              animate={{ opacity: 1, y: 0 }}
              exit={{ opacity: 0, y: -10 }}
              className="space-y-6"
            >
              <div className="bg-zinc-900 border border-white/5 rounded-3xl p-6 space-y-6">
                <div className="flex justify-between items-center">
                  <span className="text-zinc-500 font-medium">Sending</span>
                  <div className="text-right">
                    <div className="font-bold text-white">{formatAmount(amountValue)} {nativeSymbol}</div>
                    <div className="text-xs text-zinc-500">${formatUsd(amountValue * nativePrice)}</div>
                  </div>
                </div>
                <div className="flex justify-between items-center">
                  <span className="text-zinc-500 font-medium">To</span>
                  <div className="text-right">
                    <div className="font-mono text-white text-sm">{resolvedAddress}</div>
                  </div>
                </div>
                <div className="flex justify-between items-center">
                  <span className="text-zinc-500 font-medium">Network</span>
                  <div className="text-right text-sm text-white">{preparation.network}</div>
                </div>
              </div>

              <div>
                <div className="flex items-center justify-between mb-3 px-1">
                  <span className="text-sm font-medium text-zinc-400">Transaction Speed</span>
                  <span className="text-xs font-medium text-indigo-400">
                    Est. Gas: ${formatUsd(gasFees[speed].fiat)}
                  </span>
                </div>
                <div className="grid grid-cols-3 gap-2">
                  {(['slow', 'standard', 'fast'] as const).map((option) => (
                    <button
                      key={option}
                      onClick={() => setSpeed(option)}
                      className={cn(
                        "flex flex-col items-center py-3 rounded-2xl border transition-all",
                        speed === option 
                          ? "bg-indigo-500/10 border-indigo-500/50 text-white" 
                          : "bg-zinc-900 border-white/5 text-zinc-500 hover:border-white/10"
                      )}
                    >
                      <span className="text-xs font-bold uppercase tracking-wider mb-1">{option}</span>
                      <span className="text-[10px] opacity-60">{gasFees[option].time}</span>
                    </button>
                  ))}
                </div>
              </div>

              <div className="bg-indigo-500/5 border border-indigo-500/10 rounded-2xl p-4">
                <div className="flex items-center justify-between mb-2">
                  <div className="flex items-center gap-2">
                    <ShieldCheck className="w-5 h-5 text-indigo-400" />
                    <span className="font-medium text-indigo-100 text-sm">
                      {isProtectedExecution ? 'Oxidity Protection' : 'Direct Broadcast'}
                    </span>
                  </div>
                  <Info className="w-4 h-4 text-indigo-400/50" />
                </div>
                <p className="text-xs text-indigo-300/60 leading-relaxed">
                  {isProtectedExecution
                    ? 'Your transaction will be sent through the private relay path.'
                    : 'This chain will broadcast directly to the network because private relay routing is unavailable.'}
                </p>
              </div>

              <button 
                onClick={() => void handleConfirm()}
                disabled={isBroadcasting}
                className="w-full bg-indigo-500 text-white font-bold py-4 rounded-2xl hover:bg-indigo-600 transition-colors shadow-[0_0_20px_rgba(99,102,241,0.3)] disabled:opacity-60"
              >
                {isBroadcasting ? 'Broadcasting...' : 'Confirm Send'}
              </button>
            </motion.div>
          )}

          {step === 'success' && (
            <motion.div
              key="success"
              initial={{ opacity: 0, scale: 0.9 }}
              animate={{ opacity: 1, scale: 1 }}
              className="flex flex-col items-center justify-center py-12 text-center"
            >
              <div className="w-20 h-20 bg-emerald-500/20 rounded-full flex items-center justify-center mb-6">
                <Check className="w-10 h-10 text-emerald-500" />
              </div>
              <h3 className="text-2xl font-bold text-white mb-2">Transaction Sent</h3>
              <p className="text-zinc-500 mb-8 max-w-[240px]">
                {isProtectedExecution
                  ? 'Your transaction was submitted through the protected relay path.'
                  : 'Your transaction has been broadcasted to the network.'}
              </p>
              
              <div className="w-full bg-zinc-900 border border-white/5 rounded-3xl p-6 mb-8 text-left">
                <div className="flex justify-between mb-4">
                  <span className="text-zinc-500 text-sm">Amount</span>
                  <span className="text-white font-semibold">{formatAmount(amountValue)} {nativeSymbol}</span>
                </div>
                <div className="flex justify-between">
                  <span className="text-zinc-500 text-sm">To</span>
                  <span className="text-white font-mono text-sm">
                    {(resolvedAddress || address).slice(0, 6)}...{(resolvedAddress || address).slice(-4)}
                  </span>
                </div>
              </div>

              {explorerUrl && (
                <a
                  href={explorerUrl}
                  target="_blank"
                  rel="noreferrer"
                  onClick={(event) => {
                    event.preventDefault();
                    void openExternalUrl(explorerUrl);
                  }}
                  className="w-full mb-4 bg-indigo-500/10 text-indigo-300 font-medium py-4 rounded-2xl border border-indigo-500/20 hover:bg-indigo-500/20 transition-colors flex items-center justify-center gap-2"
                >
                  View on Explorer
                  <ExternalLink className="w-4 h-4" />
                </a>
              )}

              {!isAddressSaved && (
                <div className="w-full bg-indigo-500/10 border border-indigo-500/20 rounded-3xl p-6 mb-8 text-left">
                  {isSaving ? (
                    <div className="space-y-4">
                      <h4 className="font-semibold text-white">Save Address</h4>
                      <input
                        type="text"
                        placeholder="Name (e.g. Alice)"
                        value={saveName}
                        onChange={(event) => setSaveName(event.target.value)}
                        className="w-full bg-zinc-900 border border-white/10 rounded-xl py-3 px-4 text-sm text-white placeholder:text-zinc-500 focus:outline-none focus:border-indigo-500/50 transition-colors"
                      />
                      <div className="flex gap-3">
                        <button 
                          onClick={() => setIsSaving(false)}
                          className="flex-1 py-2.5 bg-zinc-900 hover:bg-zinc-800 text-white text-sm font-medium rounded-xl transition-colors"
                        >
                          Cancel
                        </button>
                        <button 
                          onClick={handleSaveAddress}
                          disabled={!saveName}
                          className="flex-1 py-2.5 bg-indigo-600 hover:bg-indigo-700 disabled:opacity-50 text-white text-sm font-medium rounded-xl transition-colors"
                        >
                          Save
                        </button>
                      </div>
                    </div>
                  ) : (
                    <div className="flex items-center justify-between">
                      <div>
                        <h4 className="font-semibold text-white mb-1">Save this address?</h4>
                        <p className="text-xs text-indigo-300/60">Add to your address book for next time.</p>
                      </div>
                      <button 
                        onClick={() => setIsSaving(true)}
                        className="w-10 h-10 bg-indigo-500/20 rounded-full flex items-center justify-center hover:bg-indigo-500/30 transition-colors"
                      >
                        <Plus className="w-5 h-5 text-indigo-400" />
                      </button>
                    </div>
                  )}
                </div>
              )}

              <button 
                onClick={() => setView('main')}
                className="w-full bg-zinc-900 text-white font-bold py-4 rounded-2xl border border-white/5 hover:bg-zinc-800 transition-colors"
              >
                Done
              </button>
            </motion.div>
          )}
        </AnimatePresence>
      </div>
    </ScreenWrapper>
  );
}
