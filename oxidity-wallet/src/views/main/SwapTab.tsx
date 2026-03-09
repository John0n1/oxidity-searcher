import { useEffect, useMemo, useState } from 'react';
import { Capacitor } from '@capacitor/core';
import { motion, AnimatePresence } from 'motion/react';
import { ArrowDown, Settings2, ShieldCheck, Zap, Info, ChevronDown, ExternalLink, Search, X } from 'lucide-react';
import { Wallet } from 'ethers';

import { cn } from '../../utils/cn';
import { TokenLogo } from '../../components/TokenLogo';
import { useAppStore } from '../../store/appStore';
import {
  broadcastSignedSend,
  getCatalog,
  getQuotePreview,
  prepareSwap,
  type QuotePreviewResponse,
  type SwapPrepareResponse,
} from '../../lib/api';
import { openExternalUrl } from '../../lib/external';

type Speed = 'slow' | 'standard' | 'fast';
type SwapTokenOption = {
  symbol: string;
  name: string;
  address: string;
  logo?: string;
};

const SPEED_LABELS: Record<Speed, { time: string; multiplier: bigint }> = {
  slow: { time: '< 5 min', multiplier: 95n },
  standard: { time: '< 2 min', multiplier: 100n },
  fast: { time: '< 30 sec', multiplier: 125n },
};
const DEFAULT_BUY_TOKEN: SwapTokenOption = {
  symbol: 'USDC',
  name: 'USD Coin',
  address: '',
  logo: 'https://cryptologos.cc/logos/usd-coin-usdc-logo.png',
};

function formatUsd(value: number): string {
  return value.toLocaleString('en-US', {
    minimumFractionDigits: 2,
    maximumFractionDigits: 2,
  });
}

function formatAmount(value: number | string): string {
  const numeric = typeof value === 'string' ? Number(value) : value;
  if (!Number.isFinite(numeric)) {
    return '0';
  }
  const rendered = numeric.toFixed(6).replace(/\.?0+$/, '');
  return rendered.length > 0 ? rendered : '0';
}

function scaleWei(value: string, multiplier: bigint): bigint {
  return (BigInt(value) * multiplier + 99n) / 100n;
}

export function SwapTab() {
  const isNativePlatform = Capacitor.isNativePlatform();
  const ScreenWrapper: any = isNativePlatform ? 'div' : motion.div;
  const PanelWrapper: any = isNativePlatform ? 'div' : motion.div;
  const OverlayWrapper: any = isNativePlatform ? 'div' : motion.div;
  const ModalWrapper: any = isNativePlatform ? 'div' : motion.div;
  const activeChainKey = useAppStore((state) => state.activeChainKey);
  const accounts = useAppStore((state) => state.accounts);
  const activeAccountId = useAppStore((state) => state.activeAccountId);
  const nativeAsset = useAppStore((state) => state.nativeAsset);
  const exportActivePrivateKey = useAppStore((state) => state.exportActivePrivateKey);
  const refreshWalletData = useAppStore((state) => state.refreshWalletData);

  const activeAccount = accounts.find((account) => account.id === activeAccountId);
  const nativeSymbol = nativeAsset?.symbol || 'ETH';
  const nativeBalance = nativeAsset?.rawBalance || 0;
  const nativePrice =
    nativeAsset && nativeAsset.rawBalance > 0
      ? nativeAsset.fiatValue / nativeAsset.rawBalance
      : 0;

  const [amountIn, setAmountIn] = useState('');
  const [amountOut, setAmountOut] = useState('');
  const [quote, setQuote] = useState<QuotePreviewResponse | null>(null);
  const [swapPreparation, setSwapPreparation] = useState<SwapPrepareResponse | null>(null);
  const [isReviewing, setIsReviewing] = useState(false);
  const [speed, setSpeed] = useState<Speed>('standard');
  const [isPreparing, setIsPreparing] = useState(false);
  const [isBroadcasting, setIsBroadcasting] = useState(false);
  const [errorMessage, setErrorMessage] = useState<string | null>(null);
  const [explorerUrl, setExplorerUrl] = useState('');
  const [slippageBps, setSlippageBps] = useState(100);
  const [buyToken, setBuyToken] = useState<SwapTokenOption>(DEFAULT_BUY_TOKEN);
  const [availableBuyTokens, setAvailableBuyTokens] = useState<SwapTokenOption[]>([DEFAULT_BUY_TOKEN]);
  const [tokenSearch, setTokenSearch] = useState('');
  const [isTokenPickerOpen, setIsTokenPickerOpen] = useState(false);
  const [isSettingsOpen, setIsSettingsOpen] = useState(false);

  const amountValue = Number(amountIn);
  const executionMode = swapPreparation?.executionMode || quote?.executionMode || 'direct';
  const isProtectedExecution = executionMode === 'protected';
  const activeBuyToken = swapPreparation?.buySymbol || buyToken.symbol;
  const swapSupported = activeChainKey !== 'solana';

  const gasFees = useMemo(() => {
    const base = swapPreparation?.estimatedFeeUsd || quote?.estimatedGasUsd || 0;
    return {
      slow: { eth: '0.0000', fiat: Math.max(0, base * 0.9), time: SPEED_LABELS.slow.time },
      standard: { eth: '0.0000', fiat: base, time: SPEED_LABELS.standard.time },
      fast: { eth: '0.0000', fiat: base * 1.25, time: SPEED_LABELS.fast.time },
    };
  }, [quote, swapPreparation]);

  const filteredBuyTokens = useMemo(() => {
    const search = tokenSearch.trim().toLowerCase();
    return availableBuyTokens
      .filter((token) => token.symbol.toUpperCase() !== nativeSymbol.toUpperCase())
      .filter((token) => {
        if (!search) {
          return true;
        }
        return (
          token.symbol.toLowerCase().includes(search) ||
          token.name.toLowerCase().includes(search)
        );
      });
  }, [availableBuyTokens, nativeSymbol, tokenSearch]);

  useEffect(() => {
    let cancelled = false;

    void getCatalog()
      .then((catalog) => {
        if (cancelled) {
          return;
        }
        const chainCatalog = catalog.find((entry) => entry.chainKey === activeChainKey);
        const tokens = chainCatalog?.tokens?.length
          ? chainCatalog.tokens.map((token) => ({
              symbol: token.symbol,
              name: token.name,
              address: token.address,
              logo: token.logo,
            }))
          : [DEFAULT_BUY_TOKEN];
        setAvailableBuyTokens(tokens);

        const preferredToken =
          tokens.find((token) => token.symbol.toUpperCase() === buyToken.symbol.toUpperCase())
          || tokens.find((token) => token.symbol.toUpperCase() === 'USDC')
          || tokens.find((token) => token.symbol.toUpperCase() !== nativeSymbol.toUpperCase())
          || tokens[0]
          || DEFAULT_BUY_TOKEN;
        setBuyToken(preferredToken);
      })
      .catch(() => {
        if (!cancelled) {
          setAvailableBuyTokens([DEFAULT_BUY_TOKEN]);
          setBuyToken(DEFAULT_BUY_TOKEN);
        }
      });

    return () => {
      cancelled = true;
    };
  }, [activeChainKey, nativeSymbol]);

  useEffect(() => {
    let cancelled = false;
    if (!amountIn.trim() || !Number.isFinite(amountValue) || amountValue <= 0) {
      setAmountOut('');
      setQuote(null);
      return () => {
        cancelled = true;
      };
    }

    const timeout = window.setTimeout(() => {
      void getQuotePreview({
        chainKey: activeChainKey,
        sellToken: nativeSymbol,
        buyToken: buyToken.symbol,
        sellAmount: amountIn.trim(),
      })
        .then((nextQuote) => {
          if (cancelled) {
            return;
          }
          setQuote(nextQuote);
          setAmountOut(formatAmount(nextQuote.receiveAmount));
        })
        .catch(() => {
          if (cancelled) {
            return;
          }
          setQuote(null);
          setAmountOut('');
        });
    }, 250);

    return () => {
      cancelled = true;
      window.clearTimeout(timeout);
    };
  }, [activeChainKey, amountIn, amountValue, buyToken.symbol, nativeSymbol]);

  const handleSwap = async () => {
    if (!activeAccount) {
      setErrorMessage('No active wallet is available');
      return;
    }
    if (!Number.isFinite(amountValue) || amountValue <= 0) {
      setErrorMessage('Enter a valid swap amount');
      return;
    }
    if (amountValue > nativeBalance) {
      setErrorMessage(`Amount exceeds available ${nativeSymbol} balance`);
      return;
    }

    setIsPreparing(true);
    setErrorMessage(null);
    try {
      const preparation = await prepareSwap({
        chainKey: activeChainKey,
        walletAddress: activeAccount.address,
        sellToken: nativeSymbol,
        buyToken: buyToken.symbol,
        sellAmount: amountIn.trim(),
        slippageBps,
      });
      setSwapPreparation(preparation);
      setAmountOut(preparation.expectedOutFormatted);
      setIsReviewing(true);
    } catch (error) {
      setErrorMessage(error instanceof Error ? error.message : 'Failed to prepare swap');
    } finally {
      setIsPreparing(false);
    }
  };

  const handleConfirm = async () => {
    if (!activeAccount || !swapPreparation) {
      setErrorMessage('Swap is not ready');
      return;
    }

    setIsBroadcasting(true);
    setErrorMessage(null);
    try {
      const privateKey = await exportActivePrivateKey();
      const wallet = new Wallet(privateKey);
      const multiplier = SPEED_LABELS[speed].multiplier;
      const maxPriorityFeePerGas = scaleWei(swapPreparation.maxPriorityFeePerGas, multiplier);
      let maxFeePerGas = scaleWei(swapPreparation.maxFeePerGas, multiplier);
      if (maxFeePerGas <= maxPriorityFeePerGas) {
        maxFeePerGas = maxPriorityFeePerGas + 1n;
      }

      const rawTransaction = await wallet.signTransaction({
        chainId: swapPreparation.chainId,
        nonce: swapPreparation.nonce,
        type: 2,
        to: swapPreparation.to,
        data: swapPreparation.data,
        value: BigInt(swapPreparation.value),
        gasLimit: BigInt(swapPreparation.gasLimit),
        maxFeePerGas,
        maxPriorityFeePerGas,
      });

      const response = await broadcastSignedSend({
        chainKey: activeChainKey,
        rawTransaction,
        walletAddress: activeAccount.address,
        txType: 'swap',
        title: `Swap ${nativeSymbol} to ${swapPreparation.buySymbol}`,
        amount: `-${formatAmount(amountValue)} ${nativeSymbol}`,
        fiatAmount: `-${formatUsd(amountValue * nativePrice)}`,
        asset: swapPreparation.buySymbol,
        to: swapPreparation.to,
        fee: `$${formatUsd(gasFees[speed].fiat)}`,
      });

      setExplorerUrl(response.explorerUrl);
      await refreshWalletData();
    } catch (error) {
      setErrorMessage(error instanceof Error ? error.message : 'Failed to broadcast swap');
    } finally {
      setIsBroadcasting(false);
    }
  };

  const handleTokenSelection = (token: SwapTokenOption) => {
    setBuyToken(token);
    setTokenSearch('');
    setIsTokenPickerOpen(false);
    setExplorerUrl('');
    setSwapPreparation(null);
    setQuote(null);
    setAmountOut('');
    setErrorMessage(null);
  };

  const handleSetMaxAmount = () => {
    setAmountIn(formatAmount(nativeBalance));
    setExplorerUrl('');
    setSwapPreparation(null);
    setErrorMessage(null);
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
      <div className="flex items-center justify-between p-6 pb-4 sticky top-0 bg-zinc-950/80 backdrop-blur-xl z-10 border-b border-white/5">
        <h2 className="text-2xl font-semibold tracking-tight">Swap</h2>
        <button
          onClick={() => setIsSettingsOpen(true)}
          className="w-10 h-10 bg-zinc-900 border border-white/5 rounded-full flex items-center justify-center hover:bg-zinc-800 transition-colors"
        >
          <Settings2 className="w-5 h-5 text-zinc-400" />
        </button>
      </div>

      <div className="px-6 py-4">
        {!swapSupported ? (
          <div className="rounded-3xl border border-white/5 bg-zinc-900 p-6 text-center">
            <h3 className="mb-2 text-xl font-semibold text-white">Swap is not live on Solana yet</h3>
            <p className="text-sm text-zinc-500">
              Sending, receiving, balances, and activity are available on Solana. Router-backed swap stays on the EVM path for now.
            </p>
          </div>
        ) : (
          <>
        {errorMessage && <p className="mb-4 text-sm text-red-400">{errorMessage}</p>}
        <AnimatePresence mode="wait">
          {!isReviewing ? (
            <PanelWrapper
              key="input"
              {...(!isNativePlatform
                ? {
                    initial: { opacity: 0, scale: 0.95 },
                    animate: { opacity: 1, scale: 1 },
                    exit: { opacity: 0, scale: 0.95 },
                  }
                : {})}
              className="space-y-2 relative"
            >
              <div className="bg-zinc-900 border border-white/5 rounded-3xl p-5 hover:border-white/10 transition-colors">
                <div className="flex justify-between mb-2">
                  <span className="text-sm font-medium text-zinc-500">You pay</span>
                  <span className="text-sm font-medium text-zinc-500">
                    Balance: {formatAmount(nativeBalance)}
                  </span>
                </div>
                <div className="flex items-center justify-between gap-4">
                  <input
                    type="number"
                    placeholder="0"
                    value={amountIn}
                    onChange={(e) => {
                      setAmountIn(e.target.value);
                      setExplorerUrl('');
                      setSwapPreparation(null);
                      setErrorMessage(null);
                    }}
                    className="bg-transparent text-4xl font-semibold text-white placeholder:text-zinc-700 focus:outline-none w-full"
                  />
                  <button
                    onClick={handleSetMaxAmount}
                    className="flex items-center gap-2 bg-zinc-800 hover:bg-zinc-700 transition-colors px-4 py-2 rounded-full shrink-0"
                  >
                    <TokenLogo
                      symbol={nativeSymbol}
                      logo={nativeAsset?.logo}
                      className="w-6 h-6"
                    />
                    <span className="font-semibold">{nativeSymbol}</span>
                    <ChevronDown className="w-4 h-4 text-zinc-400" />
                  </button>
                </div>
                <div className="text-sm text-zinc-500 mt-2">
                  ${formatUsd(Number.isFinite(amountValue) ? amountValue * nativePrice : 0)}
                </div>
              </div>

              <div className="absolute top-[108px] left-1/2 -translate-x-1/2 -translate-y-1/2 z-10">
                <button
                  onClick={() => setIsTokenPickerOpen(true)}
                  className="w-12 h-12 bg-zinc-950 border-[4px] border-zinc-950 rounded-2xl flex items-center justify-center hover:bg-zinc-800 transition-colors"
                >
                  <ArrowDown className="w-5 h-5 text-zinc-400" />
                </button>
              </div>

              <div className="bg-zinc-900 border border-white/5 rounded-3xl p-5 hover:border-white/10 transition-colors">
                <div className="flex justify-between mb-2">
                  <span className="text-sm font-medium text-zinc-500">You receive</span>
                  <span className="text-sm font-medium text-zinc-500">Balance: 0.00</span>
                </div>
                <div className="flex items-center justify-between gap-4">
                  <input
                    type="number"
                    placeholder="0"
                    value={amountOut}
                    onChange={() => undefined}
                    className="bg-transparent text-4xl font-semibold text-white placeholder:text-zinc-700 focus:outline-none w-full"
                    readOnly
                  />
                  <button
                    onClick={() => setIsTokenPickerOpen(true)}
                    className="flex items-center gap-2 bg-indigo-500 hover:bg-indigo-600 transition-colors px-4 py-2 rounded-full shrink-0"
                  >
                    <TokenLogo
                      symbol={buyToken.symbol}
                      logo={buyToken.logo}
                      className="w-6 h-6"
                    />
                    <span className="font-semibold">{buyToken.symbol}</span>
                    <ChevronDown className="w-4 h-4 text-indigo-200" />
                  </button>
                </div>
                <div className="text-sm text-zinc-500 mt-2">
                  ${formatUsd(quote?.receiveUsdValue || 0)}
                </div>
              </div>

              <div className="mt-6">
                <div className="flex items-center justify-between mb-3 px-1">
                  <span className="text-sm font-medium text-zinc-400">Transaction Speed</span>
                  <div className="text-right">
                    <div className="text-xs font-medium text-indigo-400">
                      Est. Gas: ${formatUsd(gasFees[speed].fiat)}
                    </div>
                    <div className="text-[10px] uppercase tracking-wider text-zinc-500">
                      Slippage {formatAmount(slippageBps / 100)}%
                    </div>
                  </div>
                </div>
                <div className="grid grid-cols-3 gap-2">
                  {(['slow', 'standard', 'fast'] as const).map((s) => (
                    <button
                      key={s}
                      onClick={() => setSpeed(s)}
                      className={cn(
                        'flex flex-col items-center py-3 rounded-2xl border transition-all',
                        speed === s
                          ? 'bg-indigo-500/10 border-indigo-500/50 text-white'
                          : 'bg-zinc-900 border-white/5 text-zinc-500 hover:border-white/10',
                      )}
                    >
                      <span className="text-xs font-bold uppercase tracking-wider mb-1">{s}</span>
                      <span className="text-[10px] opacity-60">{gasFees[s].time}</span>
                    </button>
                  ))}
                </div>
              </div>

              <div className="mt-6 mb-8 bg-indigo-500/5 border border-indigo-500/10 rounded-2xl p-4">
                <div className="flex items-center justify-between mb-3">
                  <div className="flex items-center gap-2">
                    <ShieldCheck className="w-5 h-5 text-indigo-400" />
                    <span className="font-medium text-indigo-100">
                      {isProtectedExecution ? 'Private Routing Active' : 'Direct Routing'}
                    </span>
                  </div>
                  <Info className="w-4 h-4 text-indigo-400/50" />
                </div>
                <div className="flex items-center gap-2 text-sm text-indigo-300/70">
                  <Zap className="w-4 h-4" />
                  <span>
                    {isProtectedExecution
                      ? 'Swap will use the protected relay path when the chain supports it'
                      : 'Swap will broadcast directly because private relay routing is unavailable'}
                  </span>
                </div>
              </div>

              <button
                onClick={() => void handleSwap()}
                disabled={!amountIn || isPreparing}
                className="w-full bg-white text-black font-semibold py-4 rounded-2xl hover:bg-zinc-200 transition-colors disabled:opacity-50 disabled:cursor-not-allowed"
              >
                {isPreparing ? 'Preparing...' : 'Review Swap'}
              </button>
            </PanelWrapper>
          ) : (
            <PanelWrapper
              key="review"
              {...(!isNativePlatform
                ? {
                    initial: { opacity: 0, scale: 0.95 },
                    animate: { opacity: 1, scale: 1 },
                    exit: { opacity: 0, scale: 0.95 },
                  }
                : {})}
              className="space-y-4"
            >
              <div className="text-center mb-8">
                <h3 className="text-xl font-semibold mb-2">Review Swap</h3>
                <p className="text-zinc-400">Confirm transaction details</p>
              </div>

              <div className="bg-zinc-900 border border-white/5 rounded-3xl p-6">
                <div className="flex items-center justify-between mb-6">
                  <div className="flex items-center gap-3">
                    <TokenLogo symbol={nativeSymbol} logo={nativeAsset?.logo} />
                    <div>
                      <div className="font-semibold text-lg">{amountIn || '0'} {nativeSymbol}</div>
                      <div className="text-sm text-zinc-500">
                        ~${formatUsd(amountValue * nativePrice)}
                      </div>
                    </div>
                  </div>
                  <ArrowDown className="w-5 h-5 text-zinc-500" />
                  <div className="flex items-center gap-3 text-right">
                    <div>
                      <div className="font-semibold text-lg">{amountOut || '0'} {activeBuyToken}</div>
                      <div className="text-sm text-zinc-500">
                        ~${formatUsd(quote?.receiveUsdValue || 0)}
                      </div>
                    </div>
                    <TokenLogo
                      symbol={buyToken.symbol}
                      logo={buyToken.logo}
                    />
                  </div>
                </div>

                <div className="space-y-3 pt-6 border-t border-white/5">
                  <div className="flex justify-between text-sm">
                    <span className="text-zinc-400">Rate</span>
                    <span className="font-medium">
                      1 {nativeSymbol} = {formatAmount(quote?.receiveAmount || 0)} {activeBuyToken}
                    </span>
                  </div>
                  <div className="flex justify-between text-sm">
                    <span className="text-zinc-400">Router</span>
                    <span className="font-medium">{swapPreparation?.routerName || 'V2 Router'}</span>
                  </div>
                  <div className="flex justify-between text-sm">
                    <span className="text-zinc-400">Slippage</span>
                    <span className="font-medium">{formatAmount(slippageBps / 100)}%</span>
                  </div>
                  <div className="flex justify-between text-sm">
                    <span className="text-zinc-400">Network Fee</span>
                    <div className="text-right">
                      <div className="font-medium text-zinc-300">
                        ~${formatUsd(gasFees[speed].fiat)}
                      </div>
                      <div className="text-[10px] text-zinc-500 uppercase tracking-wider">
                        {speed} speed • {gasFees[speed].time}
                      </div>
                    </div>
                  </div>
                  <div className="flex justify-between text-sm">
                    <span className="text-zinc-400">Execution Mode</span>
                    <span className="font-medium text-indigo-400 flex items-center gap-1">
                      <ShieldCheck className="w-4 h-4" />
                      {isProtectedExecution ? 'Private' : 'Direct'}
                    </span>
                  </div>
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
                  className="w-full bg-indigo-500/10 text-indigo-300 font-medium py-4 rounded-2xl border border-indigo-500/20 hover:bg-indigo-500/20 transition-colors flex items-center justify-center gap-2"
                >
                  View on Explorer
                  <ExternalLink className="w-4 h-4" />
                </a>
              )}

              <div className="flex gap-3 mt-8">
                <button
                  onClick={() => setIsReviewing(false)}
                  className="flex-1 bg-zinc-900 text-white font-semibold py-4 rounded-2xl hover:bg-zinc-800 transition-colors"
                >
                  Cancel
                </button>
                <button
                  onClick={() => void handleConfirm()}
                  disabled={isBroadcasting}
                  className="flex-[2] bg-indigo-500 text-white font-semibold py-4 rounded-2xl hover:bg-indigo-600 transition-colors shadow-[0_0_20px_rgba(99,102,241,0.3)] disabled:opacity-60"
                >
                  {isBroadcasting ? 'Broadcasting...' : 'Confirm Swap'}
                </button>
              </div>
            </PanelWrapper>
          )}
        </AnimatePresence>
          </>
        )}
      </div>

      <AnimatePresence>
        {isTokenPickerOpen && (
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
                setIsTokenPickerOpen(false);
                setTokenSearch('');
              }}
              className="fixed inset-0 z-50 bg-black/80 backdrop-blur-sm"
            />
            <ModalWrapper
              {...(!isNativePlatform
                ? {
                    initial: { opacity: 0, y: 32 },
                    animate: { opacity: 1, y: 0 },
                    exit: { opacity: 0, y: 32 },
                  }
                : {})}
              className="fixed inset-x-4 top-[12%] bottom-[12%] z-50 flex flex-col rounded-[32px] border border-white/10 bg-zinc-950"
            >
              <div className="flex items-center justify-between border-b border-white/5 p-6">
                <div>
                  <h3 className="text-xl font-semibold tracking-tight">Choose token</h3>
                  <p className="text-sm text-zinc-500">Select the asset you want to receive.</p>
                </div>
                <button
                  onClick={() => {
                    setIsTokenPickerOpen(false);
                    setTokenSearch('');
                  }}
                  className="rounded-full bg-zinc-900 p-2 text-zinc-400 hover:text-white"
                >
                  <X className="w-5 h-5" />
                </button>
              </div>

              <div className="p-6">
                <div className="relative">
                  <Search className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-zinc-500" />
                  <input
                    value={tokenSearch}
                    onChange={(event) => setTokenSearch(event.target.value)}
                    placeholder="Search token..."
                    className="w-full rounded-2xl border border-white/10 bg-zinc-900 py-3 pl-10 pr-4 text-sm text-white placeholder:text-zinc-600 focus:outline-none focus:border-indigo-500/50"
                  />
                </div>
              </div>

              <div className="flex-1 space-y-3 overflow-y-auto px-6 pb-6">
                {filteredBuyTokens.map((token) => (
                  <button
                    key={`${token.symbol}:${token.address}`}
                    onClick={() => handleTokenSelection(token)}
                    className={cn(
                      "flex w-full items-center justify-between rounded-2xl border p-4 text-left transition-colors",
                      buyToken.symbol.toUpperCase() === token.symbol.toUpperCase()
                        ? "border-indigo-500/40 bg-indigo-500/10"
                        : "border-white/5 bg-zinc-900 hover:bg-zinc-800",
                    )}
                  >
                    <div className="flex items-center gap-4">
                      <TokenLogo symbol={token.symbol} logo={token.logo} address={token.address} />
                      <div>
                        <div className="font-semibold text-white">{token.symbol}</div>
                        <div className="text-xs text-zinc-500">{token.name}</div>
                      </div>
                    </div>
                    {buyToken.symbol.toUpperCase() === token.symbol.toUpperCase() ? (
                      <span className="text-xs font-semibold uppercase tracking-wider text-indigo-300">Selected</span>
                    ) : null}
                  </button>
                ))}
                {filteredBuyTokens.length === 0 ? (
                  <div className="rounded-2xl border border-white/5 bg-zinc-900 p-6 text-center text-sm text-zinc-500">
                    No router-backed tokens matched your search on this chain.
                  </div>
                ) : null}
              </div>
            </ModalWrapper>
          </>
        )}
      </AnimatePresence>

      <AnimatePresence>
        {isSettingsOpen && (
          <>
            <OverlayWrapper
              {...(!isNativePlatform
                ? {
                    initial: { opacity: 0 },
                    animate: { opacity: 1 },
                    exit: { opacity: 0 },
                  }
                : {})}
              onClick={() => setIsSettingsOpen(false)}
              className="fixed inset-0 z-50 bg-black/80 backdrop-blur-sm"
            />
            <ModalWrapper
              {...(!isNativePlatform
                ? {
                    initial: { opacity: 0, y: 32 },
                    animate: { opacity: 1, y: 0 },
                    exit: { opacity: 0, y: 32 },
                  }
                : {})}
              className="fixed inset-x-4 bottom-6 z-50 rounded-[32px] border border-white/10 bg-zinc-950 p-6"
            >
              <div className="mb-6 flex items-center justify-between">
                <div>
                  <h3 className="text-xl font-semibold tracking-tight">Swap settings</h3>
                  <p className="text-sm text-zinc-500">Route through the best live router with controlled slippage.</p>
                </div>
                <button
                  onClick={() => setIsSettingsOpen(false)}
                  className="rounded-full bg-zinc-900 p-2 text-zinc-400 hover:text-white"
                >
                  <X className="w-5 h-5" />
                </button>
              </div>

              <div className="mb-6">
                <div className="mb-3 text-xs font-bold uppercase tracking-widest text-zinc-500">
                  Max slippage
                </div>
                <div className="grid grid-cols-3 gap-3">
                  {[50, 100, 200].map((value) => (
                    <button
                      key={value}
                      onClick={() => setSlippageBps(value)}
                      className={cn(
                        "rounded-2xl border py-3 text-sm font-semibold transition-colors",
                        slippageBps === value
                          ? "border-indigo-500/40 bg-indigo-500/10 text-white"
                          : "border-white/5 bg-zinc-900 text-zinc-400 hover:bg-zinc-800",
                      )}
                    >
                      {formatAmount(value / 100)}%
                    </button>
                  ))}
                </div>
              </div>

              <div className="rounded-2xl border border-indigo-500/10 bg-indigo-500/5 p-4 text-sm text-indigo-200/80">
                Oxidity uses the backend router quote and sends the signed transaction through the configured execution path.
              </div>
            </ModalWrapper>
          </>
        )}
      </AnimatePresence>
    </ScreenWrapper>
  );
}
