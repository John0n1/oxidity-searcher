import { useMemo, useState } from 'react';
import { AnimatePresence, motion } from 'motion/react';
import { ArrowDown, ArrowUpDown, ShieldCheck, Sparkles } from 'lucide-react';
import { quoteSwapPreview } from '../../lib/api';
import type { WalletQuotePreview } from '../../types/wallet';

const TOKENS = [
  { symbol: 'ETH', label: 'Ethereum' },
  { symbol: 'USDC', label: 'USD Coin' },
  { symbol: 'USDT', label: 'Tether' },
  { symbol: 'DAI', label: 'DAI' },
];

function formatGasUsd(gasEstimateWei: string): string {
  const gasEth = Number.parseFloat(gasEstimateWei) / 1e18;
  return `$${(gasEth * 3450).toFixed(2)} est.`;
}

export function SwapTab() {
  const [sellToken, setSellToken] = useState('ETH');
  const [buyToken, setBuyToken] = useState('USDC');
  const [sellAmount, setSellAmount] = useState('');
  const [preview, setPreview] = useState<WalletQuotePreview | null>(null);
  const [loading, setLoading] = useState(false);
  const [errorMessage, setErrorMessage] = useState('');

  const sellTokenMeta = useMemo(() => TOKENS.find((token) => token.symbol === sellToken), [sellToken]);
  const buyTokenMeta = useMemo(() => TOKENS.find((token) => token.symbol === buyToken), [buyToken]);

  const handleReview = async () => {
    setLoading(true);
    setErrorMessage('');
    try {
      const nextPreview = await quoteSwapPreview({
        chainId: 1,
        sellToken,
        buyToken,
        sellAmount,
      });
      setPreview(nextPreview);
    } catch (error) {
      setErrorMessage(error instanceof Error ? error.message : 'Unable to preview swap');
    } finally {
      setLoading(false);
    }
  };

  const swapDirections = () => {
    setSellToken(buyToken);
    setBuyToken(sellToken);
    setPreview(null);
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
        <h2 className="text-2xl font-extrabold tracking-tight text-slate-950">Swap</h2>
        <p className="mt-2 text-sm leading-7 text-slate-600">
          Preview a private-ready route. Live chain health is checked first, but execution is still a later phase.
        </p>
      </div>

      <div className="px-6 py-6">
        <div className="rounded-[2rem] border border-white/80 bg-white/92 p-6 shadow-[0_24px_70px_rgba(15,23,42,0.06)]">
          <div className="space-y-3">
            <div className="rounded-[1.7rem] border border-slate-200 bg-slate-50 p-5">
              <div className="flex items-center justify-between text-sm font-semibold text-slate-500">
                <span>You pay</span>
                <span>{sellTokenMeta?.label}</span>
              </div>
              <div className="mt-3 flex items-center gap-3">
                <input
                  type="number"
                  min="0"
                  step="any"
                  value={sellAmount}
                  onChange={(event) => {
                    setSellAmount(event.target.value);
                    setPreview(null);
                  }}
                  placeholder="0.0"
                  className="w-full bg-transparent text-4xl font-extrabold tracking-tight text-slate-950 placeholder:text-slate-300 focus:outline-none"
                />
                <select
                  value={sellToken}
                  onChange={(event) => {
                    setSellToken(event.target.value);
                    setPreview(null);
                  }}
                  className="rounded-full border border-slate-200 bg-white px-4 py-2 text-sm font-semibold text-slate-950 focus:outline-none"
                >
                  {TOKENS.map((token) => (
                    <option key={token.symbol} value={token.symbol}>
                      {token.symbol}
                    </option>
                  ))}
                </select>
              </div>
            </div>

            <div className="flex justify-center">
              <button
                onClick={swapDirections}
                className="flex h-11 w-11 items-center justify-center rounded-full border border-slate-200 bg-white text-slate-600 shadow-sm transition-colors hover:text-slate-950"
              >
                <ArrowUpDown className="h-4 w-4" />
              </button>
            </div>

            <div className="rounded-[1.7rem] border border-slate-200 bg-slate-50 p-5">
              <div className="flex items-center justify-between text-sm font-semibold text-slate-500">
                <span>You receive</span>
                <span>{buyTokenMeta?.label}</span>
              </div>
              <div className="mt-3 flex items-center gap-3">
                <div className="w-full text-4xl font-extrabold tracking-tight text-slate-950">
                  {preview?.estimatedBuyAmount ?? '0.0'}
                </div>
                <select
                  value={buyToken}
                  onChange={(event) => {
                    setBuyToken(event.target.value);
                    setPreview(null);
                  }}
                  className="rounded-full border border-slate-200 bg-white px-4 py-2 text-sm font-semibold text-slate-950 focus:outline-none"
                >
                  {TOKENS.map((token) => (
                    <option key={token.symbol} value={token.symbol}>
                      {token.symbol}
                    </option>
                  ))}
                </select>
              </div>
            </div>
          </div>

          <div className="mt-5 rounded-[1.5rem] border border-blue-200 bg-blue-50 p-4">
            <div className="flex items-center gap-2 text-sm font-semibold text-blue-700">
              <ShieldCheck className="h-4 w-4" />
              Private-ready routing
            </div>
            <p className="mt-2 text-sm leading-7 text-blue-700/90">
              Quotes reflect the current policy model after a live network check. Real execution and settlement reporting come in later phases.
            </p>
          </div>

          {errorMessage ? (
            <div className="mt-5 rounded-[1.4rem] border border-rose-200 bg-rose-50 px-4 py-3 text-sm font-medium text-rose-600">
              {errorMessage}
            </div>
          ) : null}

          <button
            disabled={!sellAmount || sellToken === buyToken || loading}
            onClick={() => {
              void handleReview();
            }}
            className="mt-5 w-full rounded-[1.3rem] bg-slate-950 px-5 py-4 font-semibold text-white transition-colors hover:bg-slate-900 disabled:cursor-not-allowed disabled:opacity-50"
          >
            {loading ? 'Fetching preview…' : 'Review preview'}
          </button>

          <AnimatePresence>
            {preview ? (
              <motion.div
                initial={{ opacity: 0, y: 12 }}
                animate={{ opacity: 1, y: 0 }}
                exit={{ opacity: 0, y: 12 }}
                className="mt-5 rounded-[1.7rem] border border-slate-200 bg-slate-50 p-5"
              >
                <div className="flex items-center justify-between">
                  <div>
                    <div className="text-xs font-semibold uppercase tracking-[0.18em] text-slate-500">Quote preview</div>
                    <div className="mt-2 text-2xl font-extrabold tracking-tight text-slate-950">
                      {preview.estimatedBuyAmount} {preview.buyToken}
                    </div>
                  </div>
                  <div className="rounded-full bg-white px-3 py-2 text-xs font-semibold uppercase tracking-[0.18em] text-blue-700 shadow-sm">
                    {preview.executionMode}
                  </div>
                </div>

                <div className="mt-5 space-y-3 text-sm">
                  <div className="flex items-center justify-between">
                    <span className="text-slate-500">Price impact</span>
                    <span className="font-semibold text-slate-950">{preview.estimatedPriceImpactBps} bps</span>
                  </div>
                  <div className="flex items-center justify-between">
                    <span className="text-slate-500">Gas estimate</span>
                    <span className="font-semibold text-slate-950">{formatGasUsd(preview.gasEstimateWei)}</span>
                  </div>
                  <div className="flex items-center justify-between">
                    <span className="text-slate-500">Sponsorship eligible</span>
                    <span className="font-semibold text-slate-950">{preview.sponsorshipEligible ? 'Yes' : 'Not by default'}</span>
                  </div>
                  <div className="flex items-center justify-between">
                    <span className="text-slate-500">Rebate eligible</span>
                    <span className="font-semibold text-slate-950">{preview.rebateEligible ? 'Possible' : 'No rebate forecast'}</span>
                  </div>
                </div>

                <div className="mt-5 rounded-[1.4rem] border border-white bg-white p-4">
                  <div className="flex items-center gap-2 text-sm font-semibold text-slate-950">
                    <Sparkles className="h-4 w-4 text-blue-700" />
                    Notes
                  </div>
                  <ul className="mt-3 space-y-2 text-sm leading-7 text-slate-600">
                    {preview.notes.map((note) => (
                      <li key={note}>{note}</li>
                    ))}
                  </ul>
                </div>
              </motion.div>
            ) : null}
          </AnimatePresence>
        </div>
      </div>
    </motion.div>
  );
}
