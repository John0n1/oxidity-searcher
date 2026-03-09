import React, { useEffect, useMemo, useState } from 'react';
import { motion, AnimatePresence } from 'motion/react';
import {
  ChevronLeft,
  CreditCard,
  Smartphone,
  ArrowRight,
  CheckCircle2,
  Info,
  TrendingUp,
  Zap,
  ShieldCheck,
} from 'lucide-react';

import { useAppStore } from '../store/appStore';
import { getOnRampQuote, type OnRampProviderQuote, type OnRampQuoteResponse } from '../lib/api';
import { openExternalUrl } from '../lib/external';

function providerLogo(providerId: string): React.ReactNode {
  switch (providerId) {
    case 'ramp':
      return <Smartphone className="w-6 h-6 text-blue-500" />;
    case 'binance':
      return <TrendingUp className="w-6 h-6 text-yellow-400" />;
    default:
      return <CreditCard className="w-6 h-6 text-purple-500" />;
  }
}

export const BuyView: React.FC = () => {
  const setView = useAppStore((state) => state.setView);
  const activeChainKey = useAppStore((state) => state.activeChainKey);
  const nativeAsset = useAppStore((state) => state.nativeAsset);
  const accounts = useAppStore((state) => state.accounts);
  const activeAccountId = useAppStore((state) => state.activeAccountId);
  const activeAccount = accounts.find((account) => account.id === activeAccountId);

  const [amount, setAmount] = useState('100');
  const [selectedProvider, setSelectedProvider] = useState<string | null>(null);
  const [step, setStep] = useState<'amount' | 'provider' | 'confirm'>('amount');
  const [quote, setQuote] = useState<OnRampQuoteResponse | null>(null);
  const [isLoading, setIsLoading] = useState(false);
  const [errorMessage, setErrorMessage] = useState<string | null>(null);

  const numericAmount = parseFloat(amount) || 0;
  const buyToken = nativeAsset?.symbol || 'ETH';

  useEffect(() => {
    let cancelled = false;
    if (!activeAccount || numericAmount <= 0) {
      setQuote(null);
      return () => {
        cancelled = true;
      };
    }

    setIsLoading(true);
    setErrorMessage(null);
    const timeout = window.setTimeout(() => {
      void getOnRampQuote({
        chainKey: activeChainKey,
        walletAddress: activeAccount.address,
        amountUsd: amount,
        buyToken,
      })
        .then((response) => {
          if (cancelled) {
            return;
          }
          setQuote(response);
          setSelectedProvider((current) =>
            current && response.providers.some((provider) => provider.id === current)
              ? current
              : response.providers[0]?.id || null,
          );
        })
        .catch((error) => {
          if (cancelled) {
            return;
          }
          setQuote(null);
          setErrorMessage(error instanceof Error ? error.message : 'Failed to load provider quotes');
        })
        .finally(() => {
          if (!cancelled) {
            setIsLoading(false);
          }
        });
    }, 250);

    return () => {
      cancelled = true;
      window.clearTimeout(timeout);
    };
  }, [activeAccount, activeChainKey, amount, buyToken, numericAmount]);

  const sortedProviders = useMemo(() => {
    return [...(quote?.providers || [])].sort((a, b) => b.receiveAmount - a.receiveAmount);
  }, [quote]);

  const bestProviderId = sortedProviders[0]?.id;
  const selectedProviderData =
    sortedProviders.find((provider) => provider.id === selectedProvider) || sortedProviders[0];

  const handleContinue = () => {
    if (step === 'amount' && numericAmount > 0) {
      setStep('provider');
      return;
    }
    if (step === 'provider' && selectedProviderData) {
      setStep('confirm');
      return;
    }
    if (step === 'confirm' && selectedProviderData) {
      void openExternalUrl(selectedProviderData.checkoutUrl);
    }
  };

  return (
    <div className="flex flex-col h-full bg-[#0A0A0A] text-white overflow-hidden">
      <div className="p-6 flex items-center justify-between">
        <button
          onClick={() =>
            step === 'amount'
              ? setView('main')
              : setStep(step === 'confirm' ? 'provider' : 'amount')
          }
          className="w-10 h-10 rounded-full bg-white/5 flex items-center justify-center hover:bg-white/10 transition-colors"
        >
          <ChevronLeft className="w-6 h-6" />
        </button>
        <h2 className="text-xl font-semibold">Buy Crypto</h2>
        <div className="w-10" />
      </div>

      <div className="flex-1 overflow-y-auto px-6 pb-24">
        {errorMessage && <p className="mb-4 text-sm text-red-400">{errorMessage}</p>}
        <AnimatePresence mode="wait">
          {step === 'amount' && (
            <motion.div
              key="amount"
              initial={{ opacity: 0, x: 20 }}
              animate={{ opacity: 1, x: 0 }}
              exit={{ opacity: 0, x: -20 }}
              className="space-y-8"
            >
              <div className="text-center space-y-2">
                <p className="text-white/50 text-sm uppercase tracking-widest">Enter Amount</p>
                <div className="flex items-center justify-center space-x-2">
                  <span className="text-4xl font-light text-white/30">$</span>
                  <input
                    type="number"
                    value={amount}
                    onChange={(e) => setAmount(e.target.value)}
                    className="bg-transparent text-6xl font-light text-center w-full focus:outline-none [appearance:textfield] [&::-webkit-outer-spin-button]:appearance-none [&::-webkit-inner-spin-button]:appearance-none"
                    placeholder="0"
                    autoFocus
                  />
                </div>
                <p className="text-emerald-400 text-sm font-medium">
                  ≈ {isLoading ? 'Loading...' : `${(quote?.providers[0]?.receiveAmount || 0).toFixed(6)} ${quote?.buyToken || buyToken}`}
                </p>
              </div>

              <div className="grid grid-cols-3 gap-3">
                {['50', '100', '500'].map((val) => (
                  <button
                    key={val}
                    onClick={() => setAmount(val)}
                    className={`py-3 rounded-2xl border transition-all ${
                      amount === val
                        ? 'bg-white text-black border-white'
                        : 'bg-white/5 border-white/10 text-white hover:bg-white/10'
                    }`}
                  >
                    ${val}
                  </button>
                ))}
              </div>

              <div className="bg-white/5 rounded-3xl p-6 space-y-4">
                <div className="flex items-center justify-between">
                  <div className="flex items-center space-x-3">
                    <div className="w-10 h-10 rounded-full bg-blue-500/20 flex items-center justify-center">
                      <TrendingUp className="w-5 h-5 text-blue-500" />
                    </div>
                    <div>
                      <p className="text-sm font-medium">Market Price</p>
                      <p className="text-xs text-white/50">
                        1 {quote?.buyToken || buyToken} = $
                        {(quote?.marketPriceUsd || 0).toLocaleString('en-US', {
                          minimumFractionDigits: 2,
                          maximumFractionDigits: 2,
                        })}
                      </p>
                    </div>
                  </div>
                  <div className="text-right">
                    <p className="text-sm font-medium text-emerald-400">
                      {sortedProviders.length > 0 ? `${sortedProviders.length} live quotes` : 'Waiting'}
                    </p>
                  </div>
                </div>
              </div>
            </motion.div>
          )}

          {step === 'provider' && (
            <motion.div
              key="provider"
              initial={{ opacity: 0, x: 20 }}
              animate={{ opacity: 1, x: 0 }}
              exit={{ opacity: 0, x: -20 }}
              className="space-y-6"
            >
              <div className="space-y-2">
                <h3 className="text-lg font-medium">Select Provider</h3>
                <p className="text-sm text-white/50">Comparing rates for ${amount} purchase</p>
              </div>

              <div className="space-y-3">
                {sortedProviders.map((provider) => (
                  <button
                    key={provider.id}
                    onClick={() => setSelectedProvider(provider.id)}
                    className={`w-full p-5 rounded-3xl border transition-all text-left relative overflow-hidden ${
                      selectedProvider === provider.id
                        ? 'bg-white/10 border-white/30'
                        : 'bg-white/5 border-white/5 hover:bg-white/10'
                    }`}
                  >
                    {provider.id === bestProviderId && (
                      <div className="absolute top-0 right-0 bg-emerald-500 text-[10px] font-bold px-3 py-1 rounded-bl-xl uppercase tracking-tighter">
                        Best Rate
                      </div>
                    )}

                    <div className="flex items-center justify-between">
                      <div className="flex items-center space-x-4">
                        <div className="w-12 h-12 rounded-2xl bg-white/5 flex items-center justify-center">
                          {providerLogo(provider.id)}
                        </div>
                        <div>
                          <p className="font-semibold">{provider.name}</p>
                          <div className="flex items-center space-x-2 text-xs text-white/50">
                            <span className="flex items-center">
                              <Zap className="w-3 h-3 mr-1 text-yellow-500" />
                              {provider.deliveryTime}
                            </span>
                            <span>•</span>
                            <span className="flex items-center">
                              <ShieldCheck className="w-3 h-3 mr-1 text-blue-500" />
                              {provider.trustScore}% Trust
                            </span>
                          </div>
                        </div>
                      </div>
                      <div className="text-right">
                        <p className="font-bold text-lg">
                          {provider.receiveAmount.toFixed(6)} {quote?.buyToken || buyToken}
                        </p>
                        <p className="text-xs text-white/40">Fee: {provider.fee}%</p>
                      </div>
                    </div>
                  </button>
                ))}
              </div>

              <div className="bg-blue-500/10 border border-blue-500/20 rounded-2xl p-4 flex items-start space-x-3">
                <Info className="w-5 h-5 text-blue-500 shrink-0 mt-0.5" />
                <p className="text-xs text-blue-200/70 leading-relaxed">
                  Quotes are refreshed live from the wallet backend. Final settlement still depends
                  on provider KYC, card checks, and regional availability.
                </p>
              </div>
            </motion.div>
          )}

          {step === 'confirm' && selectedProviderData && (
            <motion.div
              key="confirm"
              initial={{ opacity: 0, scale: 0.95 }}
              animate={{ opacity: 1, scale: 1 }}
              className="space-y-8"
            >
              <div className="text-center space-y-4">
                <div className="w-20 h-20 bg-emerald-500/20 rounded-full flex items-center justify-center mx-auto">
                  <CheckCircle2 className="w-10 h-10 text-emerald-500" />
                </div>
                <div>
                  <h3 className="text-2xl font-bold">Review Order</h3>
                  <p className="text-white/50">Confirm your purchase details</p>
                </div>
              </div>

              <div className="bg-white/5 rounded-3xl p-6 space-y-4">
                <div className="flex justify-between items-center text-sm">
                  <span className="text-white/50">You Pay</span>
                  <span className="font-medium">${amount} USD</span>
                </div>
                <div className="flex justify-between items-center text-sm">
                  <span className="text-white/50">Provider</span>
                  <span className="font-medium">{selectedProviderData.name}</span>
                </div>
                <div className="flex justify-between items-center text-sm">
                  <span className="text-white/50">Provider Fee ({selectedProviderData.fee}%)</span>
                  <span className="font-medium">
                    ${((numericAmount * selectedProviderData.fee) / 100).toFixed(2)}
                  </span>
                </div>
                <div className="h-px bg-white/10 my-2" />
                <div className="flex justify-between items-center">
                  <span className="text-lg font-medium">Total Received</span>
                  <div className="text-right">
                    <p className="text-xl font-bold text-emerald-400">
                      {selectedProviderData.receiveAmount.toFixed(6)} {quote?.buyToken || buyToken}
                    </p>
                    <p className="text-xs text-white/40">≈ ${amount}</p>
                  </div>
                </div>
              </div>

              <div className="flex items-center space-x-3 text-xs text-white/40 px-4">
                <ShieldCheck className="w-4 h-4" />
                <p>Checkout opens directly with {selectedProviderData.name}.</p>
              </div>
            </motion.div>
          )}
        </AnimatePresence>
      </div>

      <div className="fixed bottom-0 left-0 right-0 p-6 bg-gradient-to-t from-[#0A0A0A] to-transparent">
        <button
          onClick={handleContinue}
          disabled={
            isLoading ||
            (step === 'amount' && numericAmount <= 0) ||
            (step === 'provider' && !selectedProviderData)
          }
          className={`w-full py-4 rounded-2xl font-bold flex items-center justify-center space-x-2 transition-all ${
            !isLoading &&
            (((step === 'amount' || step === 'provider') && numericAmount > 0) || step === 'confirm')
              ? 'bg-white text-black hover:scale-[1.02] active:scale-[0.98]'
              : 'bg-white/10 text-white/30 cursor-not-allowed'
          }`}
        >
          <span>
            {step === 'amount'
              ? isLoading
                ? 'Loading Quotes...'
                : 'Continue'
              : step === 'provider'
                ? 'Review Order'
                : 'Confirm & Pay'}
          </span>
          <ArrowRight className="w-5 h-5" />
        </button>
      </div>
    </div>
  );
};
